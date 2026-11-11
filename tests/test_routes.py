"""HTTP API (app/routes.py, app/__init__.py)."""

from __future__ import annotations

import pytest

from app import routes
from tests.conftest import CONTEXT, URI, FakeResponse
from tests.pki_helpers import make_token


def check(idx=0, uri=URI, ctx=CONTEXT):
    return {"idx": idx, "uri": uri, "validation_context": ctx}


def test_health(client):
    assert client.get("/health").get_json() == {"status": "ok"}


def test_swagger(client):
    assert "paths" in client.get("/static/swagger.json").get_json()
    assert client.get("/swagger-ui/").status_code == 200


def test_single_check(client, network, signer):
    network.lists[URI] = make_token(signer, URI, [0, 1])
    response = client.post("/status", json=check(1))
    assert response.status_code == 200
    assert response.get_json() == {
        "valid": False, "status": 1, "status_description": "INVALID", "cached": False,
    }


@pytest.mark.parametrize(
    "body",
    [
        check(idx=None),
        {"uri": URI, "validation_context": CONTEXT},
        check(idx=-1),
        check(idx="1"),
        check(idx=True),
        check(uri="ftp://issuer.test/1"),
        check(uri=5),
        check(ctx=" "),
        check(ctx=5),
    ],
)
def test_invalid_single_check(client, network, body):
    response = client.post("/status", json=body)
    assert response.status_code == 400
    assert "error" in response.get_json()
    assert network.gets == []


def test_not_json(client):
    response = client.post("/status", data="nope", content_type="text/plain")
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("setup", "status"),
    [
        ("missing", 502),
        ("untrusted", 403),
        ("out_of_range", 400),
    ],
)
def test_single_check_errors(client, network, signer, setup, status):
    if setup == "untrusted":
        network.lists[URI] = make_token(signer, URI, [0])
        network.trust = FakeResponse(json_body={"trusted": False})
    elif setup == "out_of_range":
        network.lists[URI] = make_token(signer, URI, [0] * 8)
    response = client.post("/status", json=check(idx=8 if setup == "out_of_range" else 0))
    assert response.status_code == status
    assert set(response.get_json()) == {"error"}


def test_other_status_list_error(client, monkeypatch):
    class Teapot(routes.StatusListError):
        status_code = 418

    def fail(**kwargs):
        raise Teapot("teapot")

    monkeypatch.setattr(routes, "check_status", fail)
    response = client.post("/status", json=check())
    assert (response.status_code, response.get_json()) == (418, {"error": "teapot"})


def test_batch(client, network, signer):
    network.lists[URI] = make_token(signer, URI, [0, 1])
    response = client.post(
        "/status", json={"checks": [check(0), check(1), "not an object"]}
    )
    assert response.status_code == 200
    results = response.get_json()["results"]
    assert [r["index"] for r in results] == [0, 1, 2]
    assert [r.get("valid") for r in results] == [True, False, None]
    assert results[1]["cached"] is True
    assert results[2]["_status_code"] == 400


@pytest.mark.parametrize("checks", [[], "x", None])
def test_batch_not_a_list(client, checks):
    assert client.post("/status", json={"checks": checks}).status_code == 400


def test_batch_too_large(client, configuration):
    response = client.post("/status", json={"checks": [check()] * 4})
    assert response.status_code == 400
    assert "3" in response.get_json()["error"]

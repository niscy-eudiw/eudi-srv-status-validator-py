"""Status List Token fetching, verification and decoding (app/status_list.py)."""

from __future__ import annotations

import base64
import json
import time
import zlib

import jwt
import pytest
import requests

from app import status_list
from app.status_list import (
    FetchError,
    IndexOutOfRangeError,
    InvalidTokenError,
    TrustError,
    check_status,
)
from tests.conftest import CONTEXT, URI, FakeResponse
from tests.pki_helpers import encode_list, make_signer, make_token


@pytest.mark.parametrize("bits", [1, 2, 4, 8])
def test_decode_every_index(bits):
    values = [i % (1 << bits) for i in range(40)]
    lst = encode_list(values, bits)
    assert [status_list._decode_status_list(lst, bits, i) for i in range(40)] == values


def test_decode_out_of_range():
    lst = encode_list([0] * 8, 1)
    with pytest.raises(IndexOutOfRangeError, match="0-7"):
        status_list._decode_status_list(lst, 1, 8)


@pytest.mark.parametrize(
    "lst",
    [
        base64.urlsafe_b64encode(b"not zlib").decode(),  # bad compression
        "a",  # bad base64
    ],
)
def test_decode_corrupt_list(lst):
    with pytest.raises(InvalidTokenError):
        status_list._decode_status_list(lst, 1, 0)


def test_unpadded_base64url():
    raw = zlib.compress(b"\x02")
    lst = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert status_list._decode_status_list(lst, 1, 1) == 1


def test_leaf_key_from_bad_certificate():
    with pytest.raises(InvalidTokenError, match="leaf certificate"):
        status_list._leaf_public_key_pem([base64.b64encode(b"junk").decode()])


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"ttl": 30}, 30),
        ({"ttl": 0}, 300),
        ({"ttl": "x"}, 300),
        ({}, 300),
        ({"exp": "x"}, 300),
        ({"exp": 1}, 0),
    ],
)
def test_cache_ttl(claims, expected):
    assert status_list._compute_cache_ttl(claims) == expected


def test_cache_ttl_from_exp():
    assert 95 <= status_list._compute_cache_ttl({"exp": int(time.time()) + 100}) <= 100


def test_cache_ttl_never_past_exp():
    """A 'ttl' longer than the token's remaining lifetime is capped at 'exp'."""
    ttl = status_list._compute_cache_ttl({"ttl": 3600, "exp": int(time.time()) + 60})
    assert 55 <= ttl <= 60


@pytest.mark.parametrize("bits", [1, 2, 4, 8])
def test_check_status(network, signer, bits):
    network.lists[URI] = make_token(signer, URI, [0, 1, 2 % (1 << bits)], bits=bits)
    assert check_status(URI, 0, CONTEXT) == {
        "valid": True, "status": 0, "status_description": "VALID", "cached": False,
    }
    revoked = check_status(URI, 1, CONTEXT)
    assert revoked == {"valid": False, "status": 1, "status_description": "INVALID", "cached": True}
    if bits > 1:
        assert check_status(URI, 2, CONTEXT)["status_description"] == "APPLICATION_SPECIFIC"
    assert network.gets == [URI]
    assert network.posts[0]["json"] == {"chain": signer.x5c, "verificationContext": CONTEXT}


def test_cache_is_per_validation_context(network, signer):
    """A list trusted in one context is checked again in another."""
    network.lists[URI] = make_token(signer, URI, [0])
    check_status(URI, 0, "context-a")
    network.trust = FakeResponse(json_body={"trusted": False})
    with pytest.raises(TrustError):
        check_status(URI, 0, "context-b")
    assert check_status(URI, 0, "context-a")["cached"] is True


def test_cache_expiry_refetches(network, signer, monkeypatch):
    network.lists[URI] = make_token(signer, URI, [0], ttl=10)
    check_status(URI, 0, CONTEXT)
    later = time.time() + 11
    monkeypatch.setattr("app.cache.time.time", lambda: later)
    check_status(URI, 0, CONTEXT)
    assert network.gets == [URI, URI]


def test_cache_errors_are_not_fatal(network, signer, monkeypatch):
    from app import cache

    class Broken:
        def get(self, key):
            raise RuntimeError("down")

        def set(self, key, payload, ttl):
            raise RuntimeError("down")

    monkeypatch.setattr(cache, "_cache", Broken())
    network.lists[URI] = make_token(signer, URI, [1])
    assert check_status(URI, 0, CONTEXT)["valid"] is False


@pytest.mark.parametrize(
    ("served", "message"),
    [
        (requests.exceptions.Timeout(), "Timed out"),
        (requests.exceptions.ConnectionError("refused"), "HTTP error"),
        (FakeResponse(404), "HTTP error"),
    ],
)
def test_fetch_errors(network, served, message):
    network.lists[URI] = served
    with pytest.raises(FetchError, match=message):
        check_status(URI, 0, CONTEXT)


def test_not_a_jwt(network):
    network.lists[URI] = "not a jwt"
    with pytest.raises(InvalidTokenError, match="Malformed"):
        check_status(URI, 0, CONTEXT)


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ({"typ": "JWT"}, "typ"),
        ({"typ": None}, "typ"),
        ({"x5c": None}, "x5c"),
        ({"x5c": "not a list"}, "x5c"),
    ],
)
def test_bad_header(network, signer, header, message):
    network.lists[URI] = make_token(signer, URI, [0], header=header)
    with pytest.raises(InvalidTokenError, match=message):
        check_status(URI, 0, CONTEXT)
    assert network.posts == []


def test_typ_is_case_insensitive(network, signer):
    network.lists[URI] = make_token(signer, URI, [0], header={"typ": "StatusList+JWT"})
    assert check_status(URI, 0, CONTEXT)["valid"] is True


@pytest.mark.parametrize(
    "trust",
    [FakeResponse(json_body={"trusted": False}), requests.exceptions.Timeout()],
)
def test_untrusted_chain(network, signer, trust):
    network.lists[URI] = make_token(signer, URI, [0])
    network.trust = trust
    with pytest.raises(TrustError):
        check_status(URI, 0, CONTEXT)


def test_signature_from_another_key(network, signer):
    other = make_signer()
    token = make_token(other, URI, [0], header={"x5c": signer.x5c})
    network.lists[URI] = token
    with pytest.raises(InvalidTokenError, match="signature"):
        check_status(URI, 0, CONTEXT)


def unsigned(header: dict, payload: dict) -> str:
    """A JWT with ``header`` and an empty signature (for algorithms we must refuse)."""
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{part(header)}.{part(payload)}.c2ln"


@pytest.mark.parametrize("alg", ["HS256", "none", "", None])
def test_algorithm_not_accepted(network, signer, alg):
    """The header's 'alg' is untrusted: HMAC / none / missing give a 502, never a 500."""
    header = {"typ": "statuslist+jwt", "x5c": signer.x5c}
    if alg is not None:
        header["alg"] = alg
    network.lists[URI] = unsigned(header, {"sub": URI, "iat": 1, "status_list": {"bits": 1, "lst": "eJwDAAAAAAE"}})
    with pytest.raises(InvalidTokenError, match="alg"):
        check_status(URI, 0, CONTEXT)


def test_expired(network, signer):
    network.lists[URI] = make_token(signer, URI, [0], exp=int(time.time()) - 10)
    with pytest.raises(InvalidTokenError, match="expired"):
        check_status(URI, 0, CONTEXT)


@pytest.mark.parametrize("claim", ["iat", "sub", "status_list"])
def test_missing_claim(network, signer, claim):
    network.lists[URI] = make_token(signer, URI, [0], **{claim: None})
    with pytest.raises(InvalidTokenError, match="required claim"):
        check_status(URI, 0, CONTEXT)


def test_issued_in_the_future(network, signer):
    """Other PyJWT rejections are InvalidTokenError (502), not unhandled (500)."""
    network.lists[URI] = make_token(signer, URI, [0], iat=int(time.time()) + 3600)
    with pytest.raises(InvalidTokenError, match="rejected"):
        check_status(URI, 0, CONTEXT)


def test_sub_mismatch_is_only_logged(network, signer, caplog):
    network.lists[URI] = make_token(signer, "https://elsewhere.test/1", [0])
    assert check_status(URI, 0, CONTEXT)["valid"] is True
    assert "does not match" in caplog.text


@pytest.mark.parametrize(
    ("claim", "message"),
    [
        ("not an object", "'status_list' claim"),
        ({"bits": 3, "lst": "x"}, "bits"),
        ({"bits": 1}, "lst"),
        ({"bits": 1, "lst": ""}, "lst"),
    ],
)
def test_bad_status_list_claim(network, signer, claim, message):
    network.lists[URI] = make_token(signer, URI, [0], status_list=claim)
    with pytest.raises(InvalidTokenError, match=message):
        check_status(URI, 0, CONTEXT)


def test_index_out_of_range(network, signer):
    network.lists[URI] = make_token(signer, URI, [0] * 8)
    with pytest.raises(IndexOutOfRangeError):
        check_status(URI, 8, CONTEXT)


def test_cache_off_by_default_fetches_every_check(write_config, configuration, network, signer):
    cfg = {**configuration, "cache": {"default_ttl": 300, "max_size": 4}}
    write_config(cfg)
    network.lists[URI] = make_token(signer, URI, [0])
    assert check_status(URI, 0, CONTEXT)["cached"] is False
    network.lists[URI] = make_token(signer, URI, [1])
    revoked = check_status(URI, 0, CONTEXT)
    assert revoked["valid"] is False and revoked["cached"] is False
    assert network.gets == [URI, URI]
    # The chain is the same: the trust validator is asked once.
    assert len(network.posts) == 1

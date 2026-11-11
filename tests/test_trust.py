"""Trust validator client (app/trust.py)."""

from __future__ import annotations

import base64
import time

import pytest
import requests
from cryptography import x509

from app import trust
from app.trust import TrustValidationError, call_trust_validator
from tests.conftest import CONTEXT, TRUST_URL, FakeResponse

CHAIN = ["bGVhZg==", "Y2E="]


def test_trusted_request(network):
    assert call_trust_validator(CHAIN, CONTEXT) is True
    assert network.posts == [{"url": TRUST_URL, "json": {"chain": CHAIN, "verificationContext": CONTEXT}}]


@pytest.mark.parametrize("body", [{"trusted": False, "reason": "unknown CA"}, {}])
def test_untrusted(network, body):
    network.trust = FakeResponse(json_body=body)
    assert call_trust_validator(CHAIN, CONTEXT) is False


def test_url_override(network):
    call_trust_validator(CHAIN, CONTEXT, url="https://other.test/trust", timeout=1)
    assert network.posts[0]["url"] == "https://other.test/trust"


def test_empty_chain_is_untrusted(network):
    assert call_trust_validator([], CONTEXT) is False
    assert network.posts == []


def test_url_not_configured(write_config, network):
    write_config({"trust_validator": {}})
    with pytest.raises(TrustValidationError, match="not configured"):
        call_trust_validator(CHAIN, CONTEXT)


@pytest.mark.parametrize(
    ("trust", "message"),
    [
        (requests.exceptions.Timeout(), "timed out"),
        (requests.exceptions.ConnectionError("refused"), "request failed"),
        (FakeResponse(500, text="boom"), "status 500"),
        (FakeResponse(json_body=None), "non-JSON"),
    ],
)
def test_errors(network, trust, message):
    network.trust = trust
    with pytest.raises(TrustValidationError, match=message):
        call_trust_validator(CHAIN, CONTEXT)


def test_http_error_without_response(network, monkeypatch):
    def post(*args, **kwargs):
        raise requests.exceptions.HTTPError("no response")

    monkeypatch.setattr(trust.HTTP, "post", post)
    with pytest.raises(TrustValidationError, match="status unknown"):
        call_trust_validator(CHAIN, CONTEXT)


# --- cache of positive answers ------------------------------------------------


def _leaf_expiry(signer):
    return x509.load_der_x509_certificate(base64.b64decode(signer.x5c[0])).not_valid_after_utc.timestamp()


def test_trusted_answer_is_cached(network, signer):
    assert call_trust_validator(signer.x5c, CONTEXT) is True
    assert call_trust_validator(signer.x5c, CONTEXT) is True
    assert len(network.posts) == 1


def test_cache_is_per_context_and_endpoint(network, signer):
    call_trust_validator(signer.x5c, CONTEXT)
    call_trust_validator(signer.x5c, "other-context")
    call_trust_validator(signer.x5c, CONTEXT, url="https://other.test/trust")
    assert len(network.posts) == 3


@pytest.mark.parametrize("trust", [FakeResponse(json_body={"trusted": False}), requests.exceptions.Timeout()])
def test_rejections_and_errors_are_not_cached(network, signer, trust):
    network.trust = trust
    for _ in range(2):
        try:
            call_trust_validator(signer.x5c, CONTEXT)
        except TrustValidationError:
            pass
    network.trust = FakeResponse(json_body={"trusted": True})
    assert call_trust_validator(signer.x5c, CONTEXT) is True
    assert len(network.posts) == 3


def test_cached_answer_expires(network, signer, monkeypatch):
    now = [time.time()]
    monkeypatch.setattr(trust.time, "time", lambda: now[0])
    call_trust_validator(signer.x5c, CONTEXT)
    now[0] += 300
    call_trust_validator(signer.x5c, CONTEXT)
    assert len(network.posts) == 2


def test_cached_answer_never_outlives_the_leaf(network, signer, monkeypatch):
    now = [_leaf_expiry(signer) - 10]
    monkeypatch.setattr(trust.time, "time", lambda: now[0])
    call_trust_validator(signer.x5c, CONTEXT)
    now[0] += 9
    call_trust_validator(signer.x5c, CONTEXT)
    now[0] += 2
    call_trust_validator(signer.x5c, CONTEXT)
    assert len(network.posts) == 2


def test_unreadable_leaf_is_not_cached(network):
    call_trust_validator(CHAIN, CONTEXT)
    call_trust_validator(CHAIN, CONTEXT)
    assert len(network.posts) == 2


def test_cache_disabled(write_config, configuration, network, signer):
    write_config({**configuration, "trust_validator": {**configuration["trust_validator"], "cache_ttl": 0}})
    call_trust_validator(signer.x5c, CONTEXT)
    call_trust_validator(signer.x5c, CONTEXT)
    assert len(network.posts) == 2


def test_full_cache_evicts_the_entry_expiring_first(write_config, configuration, network, signer, monkeypatch):
    write_config({**configuration, "trust_validator": {**configuration["trust_validator"], "cache_max_size": 1}})
    now = [time.time()]
    monkeypatch.setattr(trust.time, "time", lambda: now[0])
    call_trust_validator(signer.x5c, "a")
    now[0] += 1
    call_trust_validator(signer.x5c, "b")
    call_trust_validator(signer.x5c, "b")
    call_trust_validator(signer.x5c, "a")
    assert [p["json"]["verificationContext"] for p in network.posts] == ["a", "b", "a"]

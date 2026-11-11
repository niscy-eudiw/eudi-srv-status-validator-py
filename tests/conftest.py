"""Shared fixtures: a configuration file, a signer and fake HTTP endpoints."""

from __future__ import annotations

from typing import Any

import pytest
import requests
import yaml

from app import cache as app_cache
from app import config as app_config
from app import status_list as app_status_list
from app import trust as app_trust
from tests.pki_helpers import Signer, make_signer

URI = "https://issuer.test/status/1"
TRUST_URL = "https://trust.test/trust"
CONTEXT = "EU_TOKEN_STATUS_LIST"


@pytest.fixture(scope="session")
def signer() -> Signer:
    """One signer for the whole run (key generation is the slow part)."""
    return make_signer()


@pytest.fixture
def write_config(monkeypatch, tmp_path):
    """Writes ``cfg`` as the configuration file and points CONFIG_PATH at it."""

    def write(cfg: dict[str, Any] | None) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(yaml.safe_dump(cfg) if cfg is not None else "")
        monkeypatch.setenv("CONFIG_PATH", str(path))
        app_config.load_config.cache_clear()
        app_cache._cache = None

    return write


@pytest.fixture(autouse=True)
def configuration(write_config):
    """Configuration of every test (tests may write another one)."""
    cfg = {
        "server": {"max_batch_size": 3},
        "cache": {"enabled": True, "default_ttl": 300, "max_size": 4},
        "trust_validator": {"url": TRUST_URL, "timeout": 5},
        "fetch": {"timeout": 5},
        "logging": {"level": "DEBUG"},
    }
    write_config(cfg)
    app_trust.clear_trust_cache()
    yield cfg
    app_config.load_config.cache_clear()
    app_cache._cache = None
    app_trust.clear_trust_cache()


class FakeResponse:
    """The parts of requests.Response the app uses."""

    def __init__(self, status_code: int = 200, text: str = "", json_body: Any = None):
        self.status_code = status_code
        self.text = text
        self._json = json_body
        self.headers = {"Content-Type": "application/statuslist+jwt"}

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("not JSON")
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error", response=self)


class Network:
    """Fake issuer and trust validator.

    ``lists`` maps a URI to the JWT it serves, or to an exception to raise.
    ``trust`` is the trust validator's response, or an exception to raise.
    Every call is recorded in ``gets`` / ``posts``.
    """

    def __init__(self) -> None:
        self.lists: dict[str, Any] = {}
        self.trust: Any = FakeResponse(json_body={"trusted": True})
        self.gets: list[str] = []
        self.posts: list[dict[str, Any]] = []

    def get(self, url, **kwargs):
        self.gets.append(url)
        served = self.lists.get(url, FakeResponse(404))
        if isinstance(served, BaseException):
            raise served
        return served if isinstance(served, FakeResponse) else FakeResponse(text=served)

    def post(self, url, json=None, **kwargs):
        self.posts.append({"url": url, "json": json})
        if isinstance(self.trust, BaseException):
            raise self.trust
        return self.trust


@pytest.fixture
def network(monkeypatch) -> Network:
    """Replaces the HTTP sessions' get / post with a fake issuer and trust validator."""
    fake = Network()
    monkeypatch.setattr(app_status_list.HTTP, "get", fake.get)
    monkeypatch.setattr(app_trust.HTTP, "post", fake.post)
    return fake


@pytest.fixture
def client():
    from app import create_app

    return create_app().test_client()

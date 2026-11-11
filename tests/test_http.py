"""Shared HTTP sessions (app/http.py)."""

from __future__ import annotations

from email.message import Message

import requests
from requests.cookies import MockRequest, MockResponse

from app.http import POOL_MAXSIZE, new_session


def test_session_pools_connections_without_retries():
    session = new_session()
    for scheme in ("http://", "https://"):
        adapter = session.get_adapter(f"{scheme}issuer.test")
        assert adapter._pool_maxsize == POOL_MAXSIZE
        assert adapter.max_retries.total == 0


def test_session_stores_no_cookies():
    session = new_session()
    headers = Message()
    headers["Set-Cookie"] = "session=abc; Path=/"
    request = requests.Request("GET", "https://issuer.test/status/1").prepare()
    session.cookies.extract_cookies(MockResponse(headers), MockRequest(request))
    assert len(session.cookies) == 0

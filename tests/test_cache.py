"""In-memory cache (app/cache.py)."""

from __future__ import annotations

import threading

from app import cache

KEY = ("https://issuer.test/status/1", "ctx")


def make(max_size=2):
    return cache._InMemoryCache(max_size=max_size, default_ttl=60)


def test_get_missing():
    assert make().get(KEY) is None


def test_set_get_invalidate():
    c = make()
    c.set(KEY, {"a": 1}, ttl=60)
    assert c.get(KEY) == {"a": 1}
    c.invalidate(KEY)
    assert c.get(KEY) is None


def test_expiry(monkeypatch):
    c = make()
    now = [1000.0]
    monkeypatch.setattr(cache.time, "time", lambda: now[0])
    c.set(KEY, {"a": 1}, ttl=10)
    now[0] += 10
    assert c.get(KEY) == {"a": 1}
    now[0] += 1
    assert c.get(KEY) is None
    assert KEY not in c._expiry


def test_full_cache_evicts_the_entry_expiring_first():
    c = make(max_size=2)
    c.set(("a", "ctx"), {}, ttl=100)
    c.set(("b", "ctx"), {}, ttl=10)
    c.set(("c", "ctx"), {}, ttl=50)
    assert c.get(("b", "ctx")) is None
    assert c.get(("a", "ctx")) is not None and c.get(("c", "ctx")) is not None


def test_overwrite_does_not_evict():
    c = make(max_size=2)
    c.set(("a", "ctx"), {"v": 1}, ttl=100)
    c.set(("b", "ctx"), {}, ttl=100)
    c.set(("a", "ctx"), {"v": 2}, ttl=100)
    assert c.get(("a", "ctx")) == {"v": 2} and c.get(("b", "ctx")) is not None


def test_singleton_uses_configuration(configuration):
    built = cache.get_cache()
    assert built is cache.get_cache()
    assert built._max_size == configuration["cache"]["max_size"]


def test_concurrent_set_respects_max_size():
    c = make(max_size=5)

    def fill(start):
        for i in range(start, start + 50):
            c.set((str(i), "ctx"), {}, ttl=60)

    threads = [threading.Thread(target=fill, args=(n * 50,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(c._store) == len(c._expiry) == 5

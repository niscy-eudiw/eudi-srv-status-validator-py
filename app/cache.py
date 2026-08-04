# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""
Cache layer for decoded Status List payloads, keyed by URI.

In-memory (per-worker TTLCache)

The cached value is the verified JWT payload dict so that subsequent requests
for different indices hit only the bit-extraction logic, not the network.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Any

from app import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class _BaseCache(ABC):
    @abstractmethod
    def get(self, uri: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def set(self, uri: str, payload: dict[str, Any], ttl: int) -> None: ...

    @abstractmethod
    def invalidate(self, uri: str) -> None: ...


# ---------------------------------------------------------------------------
# In-memory backend
# ---------------------------------------------------------------------------


class _InMemoryCache(_BaseCache):
    """Per-worker TTL cache protected by a RLock."""

    def __init__(self, max_size: int, default_ttl: int) -> None:
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._store: dict[str, dict[str, Any]] = {}
        self._expiry: dict[str, float] = {}
        self._lock = threading.RLock()
        logger.info(
            "Using in-memory cache (max_size=%d, default_ttl=%ds)",
            max_size,
            default_ttl,
        )

    def get(self, uri: str) -> dict[str, Any] | None:
        with self._lock:
            if uri not in self._store:
                return None
            if time.time() > self._expiry[uri]:
                logger.debug("Cache entry expired: %s", uri)
                self._evict(uri)
                return None
            logger.debug("Cache hit (memory): %s", uri)
            return self._store[uri]

    def set(self, uri: str, payload: dict[str, Any], ttl: int) -> None:
        with self._lock:
            if uri not in self._store and len(self._store) >= self._max_size:
                oldest = min(self._expiry, key=lambda k: self._expiry[k])
                self._evict(oldest)
                logger.debug("Cache full – evicted: %s", oldest)
            self._store[uri] = payload
            self._expiry[uri] = time.time() + ttl
            logger.debug("Cached (memory) %s for %ds", uri, ttl)

    def invalidate(self, uri: str) -> None:
        with self._lock:
            self._evict(uri)

    def _evict(self, uri: str) -> None:
        self._store.pop(uri, None)
        self._expiry.pop(uri, None)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _build_cache() -> _BaseCache:
    cfg = config.load_config()
    cache_cfg = cfg.get("cache", {})
    default_ttl: int = cache_cfg.get("default_ttl", 43200)
    max_size: int = cache_cfg.get("max_size", 512)

    return _InMemoryCache(max_size=max_size, default_ttl=default_ttl)


# Module-level singleton, created once per worker process
_cache: _BaseCache | None = None
_cache_lock = threading.Lock()


def get_cache() -> _BaseCache:
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache = _build_cache()
    return _cache

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
Shared HTTP sessions.

A session keeps its connections open between requests, so repeated calls to
the same host skip the TCP and TLS handshakes. Sessions are shared by the
request threads; they never store cookies.
"""

from http.cookiejar import DefaultCookiePolicy

import requests
from requests.adapters import HTTPAdapter

# Connections kept open per host: enough for the concurrent requests of one process.
POOL_MAXSIZE = 32


def new_session() -> requests.Session:
    """Return a session with a pooled adapter, no retries and no cookie storage."""
    session = requests.Session()
    adapter = HTTPAdapter(pool_maxsize=POOL_MAXSIZE)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    return session

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
Trust validator client.

Calls the external trust-validation API to verify the x5c certificate
chain extracted from a Status List Token JWT header.
"""

import base64
import hashlib
import logging
import threading
import time

import requests
from cryptography import x509

from app import config
from app.http import new_session

logger = logging.getLogger(__name__)

# Trust validator calls reuse kept-alive connections.
HTTP = new_session()

# Positive answers of the trust validator: (endpoint, context, chain digest) ->
# expiry (epoch seconds). Negative answers and errors are never cached, and the
# status bits themselves are always fetched fresh.
_trusted: dict[tuple[str, str | None, str], float] = {}
_trusted_lock = threading.Lock()


class TrustValidationError(Exception):
    """Raised when the trust validator rejects the certificate chain."""


def clear_trust_cache() -> None:
    """Forget every cached trust answer."""
    with _trusted_lock:
        _trusted.clear()


def _chain_digest(chain: list[str]) -> str:
    return hashlib.sha256("\n".join(chain).encode()).hexdigest()


def _leaf_not_after(chain: list[str]) -> float | None:
    """Expiry of the leaf certificate (epoch seconds), or None if it cannot be read."""
    try:
        leaf = x509.load_der_x509_certificate(base64.b64decode(chain[0]))
    except Exception:
        return None
    return leaf.not_valid_after_utc.timestamp()


def _is_cached_trusted(key: tuple[str, str | None, str]) -> bool:
    with _trusted_lock:
        expiry = _trusted.get(key)
        if expiry is None:
            return False
        if time.time() >= expiry:
            del _trusted[key]
            return False
        return True


def _remember_trusted(key: tuple[str, str | None, str], chain: list[str], ttl: int, max_size: int) -> None:
    """Caches a positive answer for ``ttl`` seconds, never past the leaf's expiry."""
    not_after = _leaf_not_after(chain)
    if not_after is None:
        return
    expiry = min(time.time() + ttl, not_after)
    if expiry <= time.time():
        return
    with _trusted_lock:
        if key not in _trusted and len(_trusted) >= max_size:
            del _trusted[min(_trusted, key=_trusted.__getitem__)]
        _trusted[key] = expiry


def call_trust_validator(
    chain: list[str],
    validation_context: str | None = None,
    url: str | None = None,
    timeout: int | None = None,
) -> bool:
    """
    Call the external trust validator endpoint.

    Args:
        chain: List of base64-encoded (DER) certificates, leaf first.
        verification_context: Validation context label sent to the API.
        url: Override the configured endpoint URL.
        timeout: Override the configured request timeout.

    Returns:
        True if the chain is trusted; False otherwise.

    Raises:
        TrustValidationError: On network or HTTP errors.
    """
    trust_cfg = config.load_config().get("trust_validator", {})

    endpoint = url or trust_cfg.get("url")
    ctx = validation_context
    req_timeout = timeout if timeout is not None else trust_cfg.get("timeout", 10)

    if not endpoint:
        logger.critical(
            "Configuration Error: External trust verification endpoint URL is not defined."
        )
        raise TrustValidationError("trust_validator.url is not configured")

    if not chain:
        logger.error(
            "Execution Aborted: An empty or non-existent certificate chain array was submitted for validation."
        )
        return False

    cache_ttl: int = trust_cfg.get("cache_ttl", 300)
    cache_key = (endpoint, ctx, _chain_digest(chain))
    if cache_ttl > 0 and _is_cached_trusted(cache_key):
        logger.debug("Trust validator answer served from cache [Context: %s]", ctx)
        return True

    payload = {
        "chain": chain,
        "verificationContext": ctx,
    }
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
    }

    logger.info(
        "Initiating external cryptographic path evaluation. Target API: %s [Context: %s, Certificates in Chain: %d]",
        endpoint,
        ctx,
        len(chain),
    )
    logger.debug(
        "Trust validator egress payload structure: %s",
        {**payload, "chain": f"[{len(chain)} elements obfuscated for log hygiene]"},
    )

    start_time = time.perf_counter()
    try:
        response = HTTP.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=req_timeout,
        )
        duration = time.perf_counter() - start_time
        logger.debug(
            "External trust validation HTTP request finished in %.4fs. Status received: %d",
            duration,
            response.status_code,
        )

        response.raise_for_status()

    except requests.exceptions.Timeout as exc:
        duration = time.perf_counter() - start_time
        logger.error(
            "Network timeout constraint breached: Trust validator API failed to respond within limits (Limit: %ds, Total elapsed: %.2fs) to endpoint: %s",
            req_timeout,
            duration,
            endpoint,
        )
        raise TrustValidationError(
            f"Trust validator timed out after {req_timeout}s"
        ) from exc

    except requests.exceptions.HTTPError as exc:
        # Safely extract the response object attached to the exception
        err_resp = exc.response
        status_code = err_resp.status_code if err_resp is not None else 0
        response_text = err_resp.text if err_resp is not None else "No Content"

        logger.error(
            "HTTP Protocol Error: External trust validator rejected the payload request format or authorization schema. Status: %d, Response Content: %s",
            status_code,
            response_text,
            exc_info=True,
        )
        raise TrustValidationError(
            f"Trust validator request failed with status {status_code if status_code else 'unknown'}: {exc}"
        ) from exc

    except requests.exceptions.RequestException as exc:
        logger.error(
            "Transport Layer Failure: Socket connection exception while reaching trust validator endpoint %s. Error: %s",
            endpoint,
            exc,
            exc_info=True,
        )
        raise TrustValidationError(f"Trust validator request failed: {exc}") from exc

    try:
        data = response.json()
    except (ValueError, TypeError) as exc:
        logger.error(
            "Payload Contract Failure: Response body returned from trust validator was not valid JSON data structures. Error: %s",
            exc,
        )
        raise TrustValidationError(
            "Invalid non-JSON payload format returned from trust validator engine."
        ) from exc

    trusted = bool(data.get("trusted", False))

    if not trusted:
        logger.warning(
            "Trust Evaluation Denied: The submitted certificate chain was evaluated and explicitly rejected by the engine at %s [Context: %s]. Reasons/Metadata: %s",
            endpoint,
            ctx,
            data.get("reason", "No structural reason provided by endpoint metadata."),
        )
    else:
        logger.info(
            "Trust Evaluation Accepted: Certificate chain verified authentic against current corporate policy profile."
        )

    logger.debug(
        "Finalized trust status payload conversion context evaluation. Outcome: %s",
        trusted,
    )
    if trusted and cache_ttl > 0:
        _remember_trusted(cache_key, chain, cache_ttl, trust_cfg.get("cache_max_size", 256))
    return trusted

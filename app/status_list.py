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
Status List processing – draft-ietf-oauth-status-list-10.

Pipeline:
  1. Fetch the Status List Token JWT from the issuer URI.
  2. Decode the JWT header (without verification) to extract the x5c chain.
  3. Validate the chain via the external trust validator.
  4. Verify the JWT signature using the leaf certificate's public key.
  5. Validate standard JWT claims (typ, sub, exp, iat).
  6. Decompress the `lst` field and extract the bits at the requested index.
  7. Map the bit value to a human-readable status description.

Status type values (§7.1 of draft-10):
  0x00  VALID
  0x01  INVALID
"""

from __future__ import annotations

import base64
import logging
import time
import zlib
from typing import Any

import jwt as pyjwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import config
from app.trust import TrustValidationError, call_trust_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public status type constants (§7.1)
# ---------------------------------------------------------------------------
STATUS_VALID = 0x00
STATUS_INVALID = 0x01

_STATUS_LABELS: dict[int, str] = {
    STATUS_VALID: "VALID",
    STATUS_INVALID: "INVALID",
}

EXPECTED_TYP = "statuslist+jwt"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StatusListError(Exception):
    """Base class for errors in this module."""

    status_code: int = 502


class FetchError(StatusListError):
    """Could not retrieve the Status List Token from the issuer."""

    status_code = 502


class InvalidTokenError(StatusListError):
    """The JWT is structurally invalid or fails verification."""

    status_code = 502


class TrustError(StatusListError):
    """The certificate chain was rejected by the trust validator."""

    status_code = 403


class IndexOutOfRangeError(StatusListError):
    """The requested index is out of range for this Status List."""

    status_code = 400


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64url_decode_padded(s: str) -> bytes:
    """Decode base64url string, adding padding if needed."""
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def _extract_x5c(header: dict[str, Any]) -> list[str]:
    """Return the x5c chain from the JWT header, or raise InvalidTokenError."""
    x5c = header.get("x5c")
    if not x5c or not isinstance(x5c, list) or len(x5c) == 0:
        logger.error(
            "Cryptographic validation failed: JWT header lacks an 'x5c' certificate array."
        )
        raise InvalidTokenError("JWT header is missing the 'x5c' certificate chain")
    logger.debug(
        "Successfully extracted 'x5c' chain containing %d certificate(s).", len(x5c)
    )
    return x5c


def _leaf_public_key_pem(x5c: list[str]) -> bytes:
    """
    Parse the leaf (first) certificate from the x5c array and return its
    public key in PEM format, suitable for use as a PyJWT verify key.
    """
    try:
        der = base64.b64decode(x5c[0])
        cert = x509.load_der_x509_certificate(der)
        pem_bytes = cert.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        logger.debug(
            "Successfully converted x5c leaf certificate to public key PEM format."
        )
        return pem_bytes
    except Exception as exc:
        logger.error(
            "Asymmetric key extraction failure: Failed parsing leaf DER certificate. Error: %s",
            exc,
            exc_info=True,
        )
        raise InvalidTokenError(
            f"Failed to parse leaf certificate from x5c: {exc}"
        ) from exc


def _decode_status_list(lst: str, bits: int, idx: int) -> int:
    """
    Decompress the `lst` field and extract the status bits at position *idx*.
    """
    logger.debug(
        "Beginning bitwise extraction logic (bits_per_entry=%d, requested_index=%d)",
        bits,
        idx,
    )
    try:
        compressed = _b64url_decode_padded(lst)
        raw = zlib.decompress(compressed)
        logger.debug(
            "Decompressed 'lst' payload string into raw memory footprint. Total size: %d bytes",
            len(raw),
        )
    except zlib.error as exc:
        logger.error(
            "Decompressor exception: Compressed 'lst' data corrupt or unaligned. Error: %s",
            exc,
        )
        raise InvalidTokenError(
            f"Failed to decompress status list 'lst': {exc}"
        ) from exc
    except Exception as exc:
        logger.error(
            "Base64 string decode mismatch: Base64url stream transformation failed. Error: %s",
            exc,
        )
        raise InvalidTokenError(f"Failed to base64url-decode 'lst': {exc}") from exc

    bit_offset = idx * bits
    byte_index = bit_offset // 8
    bit_in_byte = bit_offset % 8

    # Calculate global range threshold
    total_alloc_indices = (len(raw) * 8) // bits
    if byte_index >= len(raw):
        logger.warning(
            "Index boundary failure: Requested index [%d] maps to byte offset %d, but buffer only has %d bytes. (Supported index range: 0-%d)",
            idx,
            byte_index,
            len(raw),
            total_alloc_indices - 1,
        )
        raise IndexOutOfRangeError(
            f"Index {idx} is out of range for this Status List "
            f"(list covers indices 0–{total_alloc_indices - 1})"
        )

    mask = (1 << bits) - 1
    status_value = (raw[byte_index] >> bit_in_byte) & mask
    logger.debug(
        "Extracted raw bit signature at offset position [%d]: %s",
        idx,
        bin(status_value),
    )
    return status_value


def _compute_cache_ttl(payload: dict[str, Any]) -> int:
    """
    Determine the cache TTL for this Status List Token.
    """
    default_ttl: int = config.get("cache", "default_ttl", 300)

    if "ttl" in payload:
        try:
            ttl = int(payload["ttl"])
            if ttl > 0:
                logger.debug(
                    "Cache calculation: Utilizing explicit 'ttl' claim value (%ds)", ttl
                )
                return ttl
            logger.warning(
                "Cache calculation anomaly: Token contained non-positive 'ttl' claim (%d). Skipping standard evaluation.",
                ttl,
            )
        except (ValueError, TypeError):
            logger.error(
                "Schema syntax mismatch: 'ttl' claim cannot be parsed into an integer parameter. Value: %s",
                payload.get("ttl"),
            )

    if "exp" in payload:
        try:
            remaining = int(payload["exp"]) - int(time.time())
            if remaining > 0:
                logger.debug(
                    "Cache calculation: Utilizing calculated remaining lifetime via 'exp' claim (%ds)",
                    remaining,
                )
                return remaining
            logger.warning(
                "Cache calculation anomaly: Token expiration 'exp' target timestamp has already passed relative to system clock."
            )
        except (ValueError, TypeError):
            logger.error(
                "Schema syntax mismatch: 'exp' claim cannot be parsed into an integer parameter. Value: %s",
                payload.get("exp"),
            )

    logger.debug(
        "Cache calculation: Defaulting cache operational TTL to standard fallback baseline profile (%ds)",
        default_ttl,
    )
    return default_ttl


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------


def check_status(uri: str, idx: int, validation_context: str) -> dict[str, Any]:
    """
    Fetch (or use cached) the Status List Token at *uri* and return the
    status of the Referenced Token at *idx*.
    """
    from app.cache import get_cache

    cache = get_cache()
    logger.info(
        "Executing evaluation pipeline request for validation target - URI: %s, Index: %d",
        uri,
        idx,
    )

    # 1. Try cache ----------------------------------------------------------
    try:
        cached_payload = cache.get(uri)
    except Exception as exc:
        logger.error(
            "Cache look-up subsystem exception: Internal error retrieving map key from memory. Error: %s",
            exc,
            exc_info=True,
        )
        cached_payload = None

    if cached_payload is not None:
        logger.info(
            "Cache subsystem HIT for URI: %s. Skipping HTTP extraction network layers.",
            uri,
        )
        return _resolve_index(cached_payload, idx, cached=True)

    logger.debug(
        "Cache subsystem MISS for URI: %s. Preparing remote transport request execution.",
        uri,
    )

    # 2. Fetch the Status List Token JWT ------------------------------------
    fetch_cfg = config.load_config().get("fetch", {})
    fetch_timeout: int = fetch_cfg.get("timeout", 10)

    logger.info(
        "Dispatching HTTP GET request to resource server endpoint location: %s", uri
    )
    try:
        resp = requests.get(
            uri,
            timeout=fetch_timeout,
            headers={"Accept": "application/statuslist+jwt, application/jwt"},
        )
        logger.debug(
            "Received HTTP response descriptor. Status code: %d, Content-Type: %s",
            resp.status_code,
            resp.headers.get("Content-Type"),
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout as exc:
        logger.error(
            "Transport layer failure: Connection timeout reached while querying issuer URI %s (Limit: %ds)",
            uri,
            fetch_timeout,
        )
        raise FetchError(f"Timed out fetching status list from {uri}") from exc
    except requests.exceptions.RequestException as exc:
        logger.error(
            "Transport layer failure: Network link error or bad HTTP response from issuer URI %s. Error: %s",
            uri,
            exc,
        )
        raise FetchError(f"HTTP error fetching status list from {uri}: {exc}") from exc

    raw_jwt: str = resp.text.strip()

    # 3. Decode header without verification to get x5c ----------------------
    try:
        unverified_header = pyjwt.get_unverified_header(raw_jwt)
        logger.debug("Decoded unverified JOSE header envelope metadata successfully.")
    except pyjwt.exceptions.DecodeError as exc:
        logger.error(
            "Parsing layer rejection: Transmitted text data cannot be parsed as a token block layout. Error: %s",
            exc,
        )
        raise InvalidTokenError(f"Malformed JWT: {exc}") from exc

    # 4. Validate JWT typ claim (§5.1) --------------------------------------
    typ = unverified_header.get("typ", "")
    if str(typ).lower() != EXPECTED_TYP:
        logger.error(
            "Specification constraint violation: 'typ' field parameter mismatch. Expected: '%s', Got: '%s'",
            EXPECTED_TYP,
            typ,
        )
        raise InvalidTokenError(f"JWT 'typ' must be '{EXPECTED_TYP}', got '{typ}'")

    # 5. Extract x5c and validate with trust validator ----------------------
    x5c = _extract_x5c(unverified_header)

    logger.info(
        "Invoking external trust infrastructure evaluation engine for validation chain..."
    )
    try:
        trusted = call_trust_validator(chain=x5c, validation_context=validation_context)
    except TrustValidationError as exc:
        logger.error(
            "External trust validation handler aborted processing execution. Error: %s",
            exc,
            exc_info=True,
        )
        raise TrustError(str(exc)) from exc

    if not trusted:
        logger.critical(
            "Security Boundary Breach: Certificate chain provided by '%s' explicitly REJECTED by validation engine rules.",
            uri,
        )
        raise TrustError(
            "Certificate chain in Status List Token was rejected by the trust validator"
        )
    logger.info(
        "External trust infrastructure validated certificate path authenticity successfully."
    )

    # 6. Verify JWT signature with leaf cert public key ---------------------
    leaf_pub_key_pem = _leaf_public_key_pem(x5c)

    alg = unverified_header.get("alg", "")
    if not alg:
        logger.error(
            "Signature protocol exception: Cryptographic signature algorithm attribute 'alg' completely missing in JOSE header block."
        )
        raise InvalidTokenError("JWT header is missing the 'alg' field")

    logger.debug(
        "Verifying token cryptographic payload footprint utilizing algorithm framework: %s",
        alg,
    )
    try:
        payload = pyjwt.decode(
            raw_jwt,
            key=leaf_pub_key_pem,
            algorithms=[alg],
            options={
                "require": ["iat", "sub", "status_list"],
                "verify_exp": True,
            },
        )
        logger.info(
            "Cryptographic signature match established. Claims extraction successfully processed."
        )
    except pyjwt.exceptions.ExpiredSignatureError as exc:
        logger.warning(
            "Token verification failure: Provided Status List Token has crossed its 'exp' lifetime limit. Error: %s",
            exc,
        )
        raise InvalidTokenError("Status List Token has expired") from exc
    except pyjwt.exceptions.InvalidSignatureError as exc:
        logger.error(
            "Cryptographic verification failure: Signature validation failed against leaf public key for URI: %s",
            uri,
        )
        raise InvalidTokenError(
            f"Status List Token signature verification failed: {exc}"
        ) from exc
    except pyjwt.exceptions.MissingRequiredClaimError as exc:
        logger.error(
            "Schema constraint failure: Token structure missing standardized protocol claim attributes. Error: %s",
            exc,
        )
        raise InvalidTokenError(
            f"Status List Token is missing a required claim: {exc}"
        ) from exc
    except pyjwt.exceptions.DecodeError as exc:
        logger.error(
            "Parsing engine failure: PyJWT engine threw unhandled internal decode exception. Error: %s",
            exc,
        )
        raise InvalidTokenError(f"Failed to decode Status List Token: {exc}") from exc

    # 7. Validate `sub` matches the requested URI (§5.1) -------------------
    sub = payload.get("sub", "")
    if sub != uri:
        logger.warning(
            "Specification identity warning: Token issuer identification claim 'sub' (%s) does not match transport location lookup URI (%s)",
            sub,
            uri,
        )

    # 8. Cache the verified payload ----------------------------------------
    ttl = _compute_cache_ttl(payload)
    try:
        cache.set(uri, payload, ttl=ttl)
        logger.info(
            "Successfully added token payload for URI: %s to operational memory cache block (TTL: %ds)",
            uri,
            ttl,
        )
    except Exception as exc:
        logger.error(
            "Cache subsystem update exception: Failed to write entry to cache. Continuing logic flow. Error: %s",
            exc,
            exc_info=True,
        )

    # 9. Resolve the requested index ----------------------------------------
    return _resolve_index(payload, idx, cached=False)


def _resolve_index(
    payload: dict[str, Any], idx: int, *, cached: bool
) -> dict[str, Any]:
    """Extract the status value at *idx* from a verified payload dict."""
    status_list_claim = payload.get("status_list")
    if not isinstance(status_list_claim, dict):
        logger.error(
            "Schema integrity failure: The structural 'status_list' claim is missing or malformed."
        )
        raise InvalidTokenError("'status_list' claim is missing or not an object")

    bits_claim = status_list_claim.get("bits")
    lst_claim = status_list_claim.get("lst")

    # 1. Type guard / validation for bits
    if bits_claim not in (1, 2, 4, 8):
        logger.error(
            "Schema constraint violation: 'status_list.bits' field contains out-of-spec allocation increment: %r",
            bits_claim,
        )
        raise InvalidTokenError(
            f"'status_list.bits' must be 1, 2, 4 or 8; got {bits_claim!r}"
        )

    # 2. Type guard / validation for lst (narrows to str)
    if not isinstance(lst_claim, str) or not lst_claim:
        logger.error(
            "Schema constraint violation: 'status_list.lst' payload bit string value is missing or unreadable."
        )
        raise InvalidTokenError("'status_list.lst' is missing or not a string")

    bits: int = bits_claim
    lst: str = lst_claim

    status_value = _decode_status_list(lst, bits, idx)
    description = _STATUS_LABELS.get(status_value, "APPLICATION_SPECIFIC")
    is_valid = status_value == STATUS_VALID

    logger.info(
        "Resolution completed. Index [%d] evaluated to token status: 0x%02X (%s). Valid state: %s",
        idx,
        status_value,
        description,
        is_valid,
    )

    return {
        "valid": is_valid,
        "status": status_value,
        "status_description": description,
        "cached": cached,
    }

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
Flask routes for the Status List checker service.

Endpoints
---------
POST /status
    Body: {"idx": <int>, "uri": "<string>"}
    Returns: {"valid": bool, "status": int, "status_description": str, "cached": bool}

GET /health
    Returns: {"status": "ok"}
"""

import logging

from flask import Blueprint, jsonify, request

from app import config
from app.status_list import (
    FetchError,
    IndexOutOfRangeError,
    InvalidTokenError,
    StatusListError,
    TrustError,
    check_status,
)

logger = logging.getLogger(__name__)

bp = Blueprint("status", __name__)


# ---------------------------------------------------------------------------
# /status
# ---------------------------------------------------------------------------


@bp.route("/status", methods=["POST"])
def status_check():
    """
    Check the validity of one or more Referenced Tokens by status list index.

    Request JSON body (single check):
        idx                 (int, required) – zero-based index of the token in the list.
        uri                 (str, required) – URI of the Status List Token endpoint.
        validation_context  (str, required) – context string required to perform trust validation.

    Request JSON body (batch check):
        checks (list, required) – list of objects, each with idx, uri, validation_context.
        Example:
            {
                "checks": [
                    {"idx": 3, "uri": "https://...", "validation_context": "ctx-a"},
                    {"idx": 7, "uri": "https://...", "validation_context": "ctx-b"}
                ]
            }

    Responses:
        200  – Check(s) completed (token may still be invalid / revoked).
               For batch requests, each item carries its own per-item status/error;
               overall response is 200 as long as the batch itself was well-formed.
        400  – Bad request (missing / wrong types, index out of range, empty batch).
        403  – Trust validation failed (single-check mode only).
        502  – Could not fetch or verify the Status List Token (single-check mode only).
    """
    logger.info("Received request on POST /status")

    body = request.get_json(silent=True)
    if body is None:
        logger.warning(
            "Malformed API request: Request body is missing or is not valid JSON. Remote addr: %s",
            request.remote_addr,
        )
        return jsonify({"error": "Request body must be JSON"}), 400

    # --- Batch mode ----------------------------------------------------
    if "checks" in body:
        checks = body.get("checks")

        if not isinstance(checks, list) or len(checks) == 0:
            logger.warning(
                "Validation failed: 'checks' must be a non-empty list. Got: %s",
                type(checks).__name__,
            )
            return jsonify({"error": "'checks' must be a non-empty list"}), 400

        server_cfg = config.load_config().get("server", {})
        MAX_BATCH_SIZE: int = server_cfg.get(
            "max_batch_size", 100
        )  # guard against abuse / huge payloads

        if len(checks) > MAX_BATCH_SIZE:
            logger.warning(
                "Validation failed: batch size %d exceeds max of %d",
                len(checks),
                MAX_BATCH_SIZE,
            )
            return jsonify(
                {"error": f"'checks' cannot exceed {MAX_BATCH_SIZE} items"}
            ), 400

        results = []
        for i, item in enumerate(checks):
            item_result = _validate_and_check(item, batch_index=i)
            results.append(item_result)

        logger.info("Batch status check completed for %d items", len(results))
        return jsonify({"results": results}), 200

    # --- Single-check mode (backward compatible) ------------------------
    single_result = _validate_and_check(body, batch_index=None)

    status_code = single_result.pop("_status_code")
    return jsonify(single_result), status_code


def _validate_and_check(item, batch_index):
    """
    Validates a single check item and runs the status check.

    Returns a dict containing '_status_code'. The caller pops it before
    returning to the client in single-check mode; batch mode leaves it in
    place for the route to strip per-item if desired (currently left as-is
    so each batch result also carries its own status_code for transparency).
    """
    if not isinstance(item, dict):
        logger.warning(
            "Validation failed [batch_index=%s]: check item is not a JSON object. Got: %s",
            batch_index,
            type(item).__name__,
        )
        return _error_result(batch_index, "Each check must be a JSON object", 400)

    idx = item.get("idx")
    uri = item.get("uri")
    validation_context = item.get("validation_context")

    logger.debug(
        "Parsing request inputs [batch_index=%s] - URI: %s, Index: %s",
        batch_index,
        uri,
        idx,
    )

    if idx is None or uri is None or validation_context is None:
        logger.warning(
            "Validation failed [batch_index=%s]: Missing required fields. "
            "Got idx=%s, uri=%s, validation_context=%s",
            batch_index,
            idx is not None,
            uri is not None,
            validation_context is not None,
        )
        return _error_result(
            batch_index,
            "'idx', 'uri', and 'validation_context' are all required",
            400,
        )

    if not isinstance(idx, int) or idx < 0:
        logger.warning(
            "Validation failed [batch_index=%s]: 'idx' must be a non-negative integer. "
            "Got value: %s (type: %s)",
            batch_index,
            idx,
            type(idx).__name__,
        )
        return _error_result(batch_index, "'idx' must be a non-negative integer", 400)

    if not isinstance(uri, str) or not uri.startswith(("http://", "https://")):
        logger.warning(
            "Validation failed [batch_index=%s]: 'uri' must be a valid HTTP(S) string. Got: %s",
            batch_index,
            uri,
        )
        return _error_result(batch_index, "'uri' must be a valid HTTP(S) URL", 400)

    if not isinstance(validation_context, str) or not validation_context.strip():
        logger.warning(
            "Validation failed [batch_index=%s]: 'validation_context' must be a non-empty string. "
            "Got type: %s",
            batch_index,
            type(validation_context).__name__,
        )
        return _error_result(
            batch_index, "'validation_context' must be a non-empty string", 400
        )

    logger.info(
        "Processing status evaluation [batch_index=%s] for URI: %s at index [%d]",
        batch_index,
        uri,
        idx,
    )

    try:
        result = check_status(uri=uri, idx=idx, validation_context=validation_context)

        logger.info(
            "Status verification successful [batch_index=%s] for URI: %s [index=%d]. "
            "Valid: %s, Status: %s (Cached: %s)",
            batch_index,
            uri,
            idx,
            result.get("valid"),
            result.get("status"),
            result.get("cached", False),
        )

        result["_status_code"] = 200
        if batch_index is not None:
            result["index"] = batch_index
        return result

    except IndexOutOfRangeError as exc:
        logger.warning(
            "Index out of range [batch_index=%s]: idx=%d uri=%s – Details: %s",
            batch_index,
            idx,
            uri,
            exc,
        )
        return _error_result(batch_index, str(exc), 400)

    except TrustError as exc:
        logger.error(
            "Trust boundary violation! [batch_index=%s] Validation failed for URI: %s. Details: %s",
            batch_index,
            uri,
            exc,
            exc_info=True,
        )
        return _error_result(batch_index, str(exc), 403)

    except (FetchError, InvalidTokenError) as exc:
        logger.error(
            "Network or cryptographic extraction error [batch_index=%s] for URI: %s. Details: %s",
            batch_index,
            uri,
            exc,
            exc_info=True,
        )
        return _error_result(batch_index, str(exc), 502)

    except StatusListError as exc:
        status_code = getattr(exc, "status_code", 500)
        logger.error(
            "Handled base StatusListError [batch_index=%s] for URI: %s. Assigned status code: %d. Details: %s",
            batch_index,
            uri,
            status_code,
            exc,
            exc_info=True,
        )
        return _error_result(batch_index, str(exc), status_code)

    except Exception as exc:  # pragma: no cover
        logger.exception(
            "Unhandled runtime error [batch_index=%s] during status verification: %s",
            batch_index,
            exc,
        )
        return _error_result(batch_index, "Internal server error", 500)


def _error_result(batch_index, message, status_code):
    result = {"error": message, "_status_code": status_code}
    if batch_index is not None:
        result["index"] = batch_index
    return result


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


@bp.route("/health", methods=["GET"])
def health():
    # Kept as DEBUG to avoid filling log aggregation streams with health-check noise every few seconds
    logger.debug("Health probe hit from client: %s", request.remote_addr)
    return jsonify({"status": "ok"}), 200

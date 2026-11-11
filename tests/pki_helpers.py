"""Throw-away certificates and signed Status List Tokens for the tests."""

from __future__ import annotations

import base64
import datetime
import time
import zlib
from typing import Any, NamedTuple

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class Signer(NamedTuple):
    """A status list signer: its key and its x5c chain (leaf first)."""

    private_key: ec.EllipticCurvePrivateKey
    x5c: list[str]


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "LU"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def make_signer() -> Signer:
    """Generates a CA and a leaf signed by it (EC P-256).

    Returns:
        The leaf key and the chain ``[leaf, CA]`` as base64 DER.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("Test status list CA"))
        .issuer_name(_name("Test status list CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("Test status list signer"))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    x5c = [
        base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
        for cert in (leaf, ca)
    ]
    return Signer(leaf_key, x5c)


def encode_list(statuses: list[int], bits: int) -> str:
    """Packs ``statuses`` (``bits`` per entry, least significant first) as ``lst``."""
    per_byte = 8 // bits
    raw = bytearray((len(statuses) + per_byte - 1) // per_byte)
    for idx, value in enumerate(statuses):
        raw[idx // per_byte] |= value << (idx % per_byte * bits)
    return base64.urlsafe_b64encode(zlib.compress(bytes(raw))).decode().rstrip("=")


def make_token(
    signer: Signer,
    uri: str,
    statuses: list[int],
    *,
    bits: int = 1,
    header: dict[str, Any] | None = None,
    **claims: Any,
) -> str:
    """Signs a Status List Token for ``uri`` (ES256, ``typ: statuslist+jwt``).

    Args:
        signer: Key and x5c chain.
        uri: The ``sub`` claim.
        statuses: One status value per index.
        bits: Bits per entry.
        header: Replaces or adds header fields (``None`` values remove them).
        **claims: Replace or add claims (``None`` values remove them).

    Returns:
        The compact JWT.
    """
    now = int(time.time())
    payload = {
        "sub": uri,
        "iat": now,
        "exp": now + 3600,
        "ttl": 600,
        "status_list": {"bits": bits, "lst": encode_list(statuses, bits)},
    }
    payload.update(claims)
    headers = {"typ": "statuslist+jwt", "x5c": signer.x5c}
    headers.update(header or {})
    return jwt.encode(
        {k: v for k, v in payload.items() if v is not None},
        signer.private_key,
        algorithm="ES256",
        headers={k: v for k, v in headers.items() if v is not None},
    )

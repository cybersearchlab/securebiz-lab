"""
app/services/context_signing.py
================================================================================
SecureBiz Lab - Identity Context Construction and Signing
================================================================================

Responsibilities:
    - Validate user and organization identifiers.
    - Build the canonical identity context payload.
    - Generate a unique request identifier (jti).
    - Sign the exact payload using Vault Transit Ed25519.
    - Return the original payload and its signature unchanged.

This module MUST NOT contain:
    - Database operations.
    - HTTP request handling.
    - Authentication or JWT validation logic.
    - Authorization or membership validation.

Security constraints:
    - iss = "securebiz-api"
    - aud = "securebiz-postgres"
    - sub and org must be valid UUIDs.
    - jti must be a fresh UUID4 for every signing operation.
    - iat = current Unix timestamp in seconds.
    - exp = iat + 30 seconds.
    - Maximum context lifetime = 60 seconds.
    - Canonical JSON: sorted keys, compact separators.
    - The exact payload string signed by Vault MUST be forwarded
      unchanged to PostgreSQL.
================================================================================
"""

import json
import time
import uuid

from app.core.vault import sign_payload

ISSUER = "securebiz-api"
AUDIENCE = "securebiz-postgres"
CONTEXT_TTL_SECONDS = 30
MAX_CONTEXT_TTL_SECONDS = 60


def _validate_uuid(value: str, field_name: str) -> str:
    """
    Validate and normalize a UUID string.

    Returns:
        Canonical UUID string (lowercase, hyphenated).

    Raises:
        ValueError: if the value is not a valid, non-zero UUID.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty UUID string")

    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(f"{field_name} is not a valid UUID: {exc}") from exc

    if parsed == uuid.UUID(int=0):
        raise ValueError(f"{field_name} must not be the nil UUID")

    return str(parsed)


def build_payload(user_id: str, org_id: str) -> str:
    """
    Build the canonical JSON payload for install_context().

    Args:
        user_id: UUID string of the authenticated user.
        org_id: UUID string of the active organization.

    Returns:
        Canonical JSON string (UTF-8, sorted keys, no spaces).

    Raises:
        ValueError: if user_id or org_id is invalid.
    """
    canonical_user = _validate_uuid(user_id, "user_id")
    canonical_org = _validate_uuid(org_id, "org_id")

    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": canonical_user,
        "org": canonical_org,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + CONTEXT_TTL_SECONDS,
    }

    # ensure_ascii=True for deterministic serialization (claims are ASCII).
    return json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
    )


def sign_context(user_id: str, org_id: str) -> tuple[str, bytes, str, int]:
    """
    Build and sign an identity context.

    Returns:
        (payload_json, signature_bytes, vault_version, key_version)

        payload_json is the EXACT string whose UTF-8 bytes were signed.
        The caller MUST forward this same string to
        auth_security.securebiz_install_context() without any modification.

    Raises:
        ValueError: if inputs invalid.
        RuntimeError: if Vault signing fails.
    """
    payload_json = build_payload(user_id, org_id)
    sig_bytes, vault_version, key_version = sign_payload(payload_json)
    return payload_json, sig_bytes, vault_version, key_version

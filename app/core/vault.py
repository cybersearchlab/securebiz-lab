"""
app/core/vault.py
================================================================================
SecureBiz Lab - HashiCorp Vault Integration
================================================================================

Responsibilities:
    • Connect to the Vault instance.
    • Ensure the Transit secrets engine is enabled.
    • Create the Ed25519 signing key if it does not exist.

This file MUST NOT contain:
    • Business logic (user validation, organization checks).
    • Context signing (handled by a dedicated security service in the future).
    • Database operations.

Design Note:
    The private key NEVER leaves Vault. FastAPI will send messages to Vault
    and receive signatures. This prevents the API server from holding the
    private key in its memory, reducing the attack surface if the API is
    compromised.

================================================================================
"""

# 1. Standard library
import os
import logging
import base64
import json

# 2. Third-party
import requests

# 3. Local
# (No local imports required for this module)

logger = logging.getLogger(__name__)

# Vault connection settings, loaded from environment variables.
# Vault connection settings, loaded from environment variables.
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
if not VAULT_TOKEN:
    raise RuntimeError(
        "VAULT_TOKEN is not configured. "
        "Set it in the environment (never commit it)."
    )
HEADERS = {"X-Vault-Token": VAULT_TOKEN}

# The name of the key within Vault's Transit engine.
KEY_NAME = "securebiz-context"

def init_vault_key() -> None:
    """
    Initialize the Ed25519 key in Vault Transit.

    ADMIN ONLY. Must be invoked from scripts/init_vault.py, NOT from the
    API runtime (Priority 10 separation). The API no longer calls this
    function; it only logs a warning at startup if Vault is not
    provisioned.

    Idempotent: safe to call multiple times.
    Raises RuntimeError if Vault is unreachable or returns a real error.

    Distinguishes:
        - 400 on mount -> already mounted (idempotent, continue)
        - 404 on key    -> key absent, create it
        - 200 on key    -> key present (normal on restart)
        - 403 anywhere  -> token lacks permission (raise)
        - 5xx anywhere  -> Vault server error (raise)
    """
    if not VAULT_TOKEN:
        raise RuntimeError("VAULT_TOKEN is not configured")

    try:
        logger.info("Initializing Vault Transit engine...")

        # Step 1: enable Transit engine (idempotent)
        r = requests.post(
            f"{VAULT_ADDR}/v1/sys/mounts/transit",
            headers=HEADERS,
            json={"type": "transit"},
            timeout=5,
        )
        if r.status_code == 400:
            # Vault returns 400 with "path is already in use" if already mounted
            body = r.text.lower()
            if "already in use" in body or "existing mount" in body:
                logger.debug("Vault: Transit already mounted.")
            else:
                raise RuntimeError(
                    f"Vault: unexpected 400 enabling transit: {r.text[:200]}"
                )
        elif r.status_code not in (200, 204):
            raise RuntimeError(
                f"Vault: status {r.status_code} enabling transit: {r.text[:200]}"
            )

        # Step 2: check if key exists
        r = requests.get(
            f"{VAULT_ADDR}/v1/transit/keys/{KEY_NAME}",
            headers=HEADERS,
            timeout=5,
        )

        if r.status_code == 404:
            # key absent -> create it
            r = requests.post(
                f"{VAULT_ADDR}/v1/transit/keys/{KEY_NAME}",
                headers=HEADERS,
                json={"type": "ed25519", "exportable": False},
                timeout=5,
            )
            if r.status_code not in (200, 204):
                raise RuntimeError(
                    f"Vault: failed to create key, status {r.status_code}: "
                    f"{r.text[:200]}"
                )
            logger.info("Vault: Ed25519 key '%s' created.", KEY_NAME)

        elif r.status_code == 200:
            # key exists -> normal on restart
            logger.info("Vault: Ed25519 key '%s' already exists.", KEY_NAME)

        elif r.status_code == 403:
            raise RuntimeError(
                "Vault: token lacks permission to read transit key. "
                "Check the Vault token policy."
            )

        else:
            raise RuntimeError(
                f"Vault: unexpected status {r.status_code} checking key: "
                f"{r.text[:200]}"
            )

    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Vault initialization failed: {exc}") from exc

def sign_payload(payload_json: str) -> tuple[bytes, str, int]:
    """
    Sign a canonical JSON payload string with Vault Transit Ed25519.

    Validated 2026-11-10: Ed25519 in Vault Transit REJECTS
    'hash_algorithm' and 'prehashed'. Only 'input' may be sent.

    Args:
        payload_json: exact UTF-8 JSON string that will later be sent
            to PostgreSQL. Caller must canonicalize with
            json.dumps(obj, separators=(",", ":"), sort_keys=True).

    Returns:
        (signature_bytes, vault_version, key_version)
        - signature_bytes: exactly 64 bytes
        - vault_version: e.g. "v1"
        - key_version: integer >= 1

    Raises:
        RuntimeError: on missing token, unreachable Vault, HTTP error,
            malformed response, or wrong signature length.
    """
    if not VAULT_TOKEN:
        raise RuntimeError("VAULT_TOKEN is not configured")
    if not payload_json:
        raise ValueError("payload_json is empty")

    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")

    try:
        r = requests.post(
            f"{VAULT_ADDR}/v1/transit/sign/{KEY_NAME}",
            headers={**HEADERS, "Content-Type": "application/json"},
            data=json.dumps({"input": payload_b64}).encode("utf-8"),
            timeout=10,
        )
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Vault Transit sign failed: {exc}") from exc

    if r.status_code != 200:
        raise RuntimeError(
            f"Vault Transit sign returned HTTP {r.status_code}: "
            f"{r.text[:200]}"
        )

    try:
        data = r.json()
        sig_full = data["data"]["signature"]
        key_version = data["data"].get("key_version")
    except (KeyError, ValueError) as exc:
        raise RuntimeError(
            f"Vault Transit sign returned malformed response: {exc}"
        ) from exc

    if not isinstance(sig_full, str) or not sig_full.startswith("vault:v"):
        raise RuntimeError("Vault Transit sign returned unexpected signature prefix")

    try:
        _, vault_version, sig_b64 = sig_full.split(":", 2)
        sig_bytes = base64.b64decode(sig_b64)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError(
            f"Vault Transit sign signature decoding failed: {exc}"
        ) from exc

    if len(sig_bytes) != 64:
        raise RuntimeError(
            f"Vault Transit sign produced {len(sig_bytes)} bytes, expected 64"
        )

    if not isinstance(key_version, int) or key_version < 1:
        raise RuntimeError(
            f"Vault Transit sign returned invalid key_version: {key_version!r}"
        )

    return sig_bytes, vault_version, key_version

# ============================================================================
# JWT HS256 secret (KV-v2)
# ============================================================================
#
# The JWT signing secret is stored in Vault KV-v2 at:
#     secret/data/securebiz/jwt
# with the shape:
#     {
#       "current":      "<64 hex chars = 32 bytes>",
#       "current_kid":  "<non-empty string>",
#       "previous":     "<64 hex chars>" or "",
#       "previous_kid": "<non-empty string>" or ""
#     }
#
# 64 hex chars encode exactly 32 bytes, i.e. 256 bits of entropy. The value
# is decoded to raw bytes so it can be used directly as the HS256 key.
#
# The result is cached at module level. Call invalidate_jwt_secret_cache()
# to force a reload (e.g. after a rotation, in tests).
# ============================================================================

JWT_SECRET_PATH = "secret/data/securebiz/jwt"

_JWT_SECRET_CACHE: tuple[bytes, str, bytes | None, str | None] | None = None


def _validate_jwt_secret_field(name: str, value: object) -> bytes:
    """
    Validate and decode one HS256 secret field.

    Accepts a non-empty string of 64 hex chars (32 bytes).
    Raises RuntimeError with a message that does NOT include the value.
    """
    if not isinstance(value, str):
        raise RuntimeError(f"Vault JWT secret: '{name}' must be a string") from None
    stripped = value.strip()
    if not stripped:
        raise RuntimeError(f"Vault JWT secret: '{name}' is empty") from None
    if len(stripped) != 64:
        raise RuntimeError(
            f"Vault JWT secret: '{name}' must be exactly 64 hex chars "
            f"(got {len(stripped)})"
        ) from None
    try:
        raw = bytes.fromhex(stripped)
    except ValueError:
        # Do NOT include 'stripped' in the message.
        raise RuntimeError(
            f"Vault JWT secret: '{name}' is not valid hexadecimal"
        ) from None
    if len(raw) != 32:
        raise RuntimeError(
            f"Vault JWT secret: '{name}' must decode to exactly 32 bytes "
            f"(got {len(raw)})"
        ) from None
    return raw


def _validate_jwt_kid(name: str, value: object) -> str:
    """Validate one kid field. Returns the trimmed string."""
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(
            f"Vault JWT secret: '{name}' must be a non-empty string"
        ) from None
    return value.strip()


def _normalize_optional(value: object) -> str | None:
    """
    Normalize a previous* field: None and "" map to None; a non-empty
    string is returned trimmed. Any other type is REJECTED explicitly
    (no silent conversion to None).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(
            "Vault JWT secret: previous/previous_kid must be a string or null"
        ) from None
    stripped = value.strip()
    return stripped or None


def get_jwt_secret() -> tuple[bytes, str, bytes | None, str | None]:
    """
    Load the HS256 JWT signing secret from Vault KV-v2.

    Path: secret/data/securebiz/jwt

    Returns:
        (current_secret, current_kid, previous_secret, previous_kid)
        - current_secret:  32 bytes
        - current_kid:     non-empty str
        - previous_secret: 32 bytes, or None if no rotation in progress
        - previous_kid:    non-empty str, or None if no rotation in progress

    Caches the result at module level. Subsequent calls return the cached
    tuple; call invalidate_jwt_secret_cache() to force a reload.

    Raises:
        RuntimeError: if Vault is unreachable, returns a non-200 status,
            the secret path is missing, the response is malformed, or any
            field fails validation. The secret value is NEVER included in
            error messages, and the original exception is NOT chained
            (from None) to avoid leaking response bodies into tracebacks.
    """
    global _JWT_SECRET_CACHE

    if _JWT_SECRET_CACHE is not None:
        return _JWT_SECRET_CACHE

    if not VAULT_TOKEN:
        raise RuntimeError("VAULT_TOKEN is not configured") from None

    url = f"{VAULT_ADDR}/v1/{JWT_SECRET_PATH}"

    try:
        r = requests.get(url, headers=HEADERS, timeout=5)
    except requests.exceptions.RequestException as exc:
        # Only the exception class name is logged; no URL, no body.
        raise RuntimeError(
            f"Vault JWT secret: request failed ({type(exc).__name__})"
        ) from None

    if r.status_code == 403:
        raise RuntimeError(
            "Vault JWT secret: token lacks permission to read "
            f"{JWT_SECRET_PATH}. Check the Vault token policy."
        ) from None
    if r.status_code == 404:
        raise RuntimeError(
            f"Vault JWT secret: not found at {JWT_SECRET_PATH}. "
            "Provision it with 'vault kv put'."
        ) from None
    if r.status_code != 200:
        raise RuntimeError(
            f"Vault JWT secret: unexpected HTTP {r.status_code} "
            f"reading {JWT_SECRET_PATH}"
        ) from None

    try:
        body = r.json()
    except ValueError:
        raise RuntimeError("Vault JWT secret: response is not valid JSON") from None

    # body must be a JSON object before any key access.
    if not isinstance(body, dict):
        raise RuntimeError(
            "Vault JWT secret: response root is not a JSON object"
        ) from None

    try:
        data = body["data"]["data"]
    except (KeyError, TypeError):
        raise RuntimeError(
            "Vault JWT secret: response missing data.data "
            "(expected KV-v2 shape)"
        ) from None

    if not isinstance(data, dict):
        raise RuntimeError("Vault JWT secret: data.data is not an object") from None

    # Required fields.
    if "current" not in data:
        raise RuntimeError("Vault JWT secret: missing 'current' field") from None
    if "current_kid" not in data:
        raise RuntimeError("Vault JWT secret: missing 'current_kid' field") from None

    current_secret = _validate_jwt_secret_field("current", data["current"])
    current_kid = _validate_jwt_kid("current_kid", data["current_kid"])

    # Optional rotation fields.
    prev_secret_raw = _normalize_optional(data.get("previous"))
    prev_kid_raw = _normalize_optional(data.get("previous_kid"))

    if (prev_secret_raw is None) != (prev_kid_raw is None):
        raise RuntimeError(
            "Vault JWT secret: 'previous' and 'previous_kid' must be "
            "provided together or both empty"
        ) from None

    if prev_secret_raw is None:
        previous_secret: bytes | None = None
        previous_kid: str | None = None
    else:
        previous_secret = _validate_jwt_secret_field("previous", prev_secret_raw)
        previous_kid = _validate_jwt_kid("previous_kid", prev_kid_raw)

    _JWT_SECRET_CACHE = (
        current_secret,
        current_kid,
        previous_secret,
        previous_kid,
    )
    logger.info(
        "Vault JWT secret loaded (kid=%s, rotation_in_progress=%s)",
        current_kid,
        previous_kid is not None,
    )
    return _JWT_SECRET_CACHE


def invalidate_jwt_secret_cache() -> None:
    """
    Clear the cached JWT secret so the next get_jwt_secret() call reloads it
    from Vault. Intended for tests and hot rotation scenarios.
    """
    global _JWT_SECRET_CACHE
    _JWT_SECRET_CACHE = None

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

    Idempotent: safe to call on every startup.
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

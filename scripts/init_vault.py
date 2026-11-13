#!/usr/bin/env python3
"""
scripts/init_vault.py
================================================================================
SecureBiz Lab - Vault provisioning script (ADMIN ONLY).

Responsibilities:
    - Enable the Transit secrets engine in Vault (idempotent).
    - Create the Ed25519 signing key (securebiz-context) if it does not exist.

This script MUST be executed ONCE before starting the API, and again
after any Vault restart in -dev mode (inmem storage loses all keys).

The API itself no longer provisions Vault. Its lifespan only logs a
warning if Vault is not provisioned. This separation ensures that the
runtime role cannot mount a secrets engine or create a key.

Usage (inside the API container, from /app):

    docker exec -w /app securebiz-api env PYTHONPATH=/app python scripts/init_vault.py

The -w /app and PYTHONPATH=/app are required so that the script can
import the 'app' package (same requirement as tests/test_*.py).

Environment variables (must be set in the container):
    - VAULT_ADDR   (default: http://vault:8200)
    - VAULT_TOKEN  (required)

Exit codes:
    0  Provisioning successful (or already provisioned).
    1  Provisioning failed (Vault unreachable, token invalid, etc.).

WARNING: This script performs administrative operations. It should be
invoked with an admin-scoped token. Do NOT call it from the API runtime.
================================================================================
"""

import sys

from app.core.vault import init_vault_key


def main() -> int:
    try:
        init_vault_key()
        print("Vault provisioning: OK")
        return 0
    except Exception as exc:
        print(f"Vault provisioning: FAILED: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
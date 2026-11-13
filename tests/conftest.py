"""
tests/conftest.py
================================================================================
Set minimal environment variables before any app.* import.

Two modules validate their environment at import time:

1. app/core/config.py instantiates Settings() at module load, which requires
   DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, AUTH_DB_USER,
   AUTH_DB_PASSWORD.

2. app/core/vault.py checks VAULT_TOKEN at module load (line 45).

The values below are never used by unit tests (get_jwt_secret is mocked),
but they must be present for the imports to succeed.

This file is auto-loaded by pytest before any test module.
================================================================================
"""

import os

# app/core/config.py — Settings() requires these
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "5433")
os.environ.setdefault("DB_NAME", "securebiz")
os.environ.setdefault("DB_USER", "test_user")
os.environ.setdefault("DB_PASSWORD", "test_pwd")
os.environ.setdefault("AUTH_DB_USER", "test_auth")
os.environ.setdefault("AUTH_DB_PASSWORD", "test_auth_pwd")

# app/core/vault.py — module-level VAULT_TOKEN check
os.environ.setdefault("VAULT_TOKEN", "test-token-never-used")
os.environ.setdefault("VAULT_ADDR", "http://vault.invalid:8200")
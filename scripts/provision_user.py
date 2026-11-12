"""
scripts/provision_user.py
================================================================================
SecureBiz Lab - Provisioning of a new Argon2id credential.

PRE-CONDITIONS (verified in Priority 8):
    - securebiz_provisioner role exists, is LOGIN, has INSERT on
      auth_private.credentials and no SELECT/UPDATE/DELETE.
    - The Vault secret secret/data/securebiz/provisioner (key db_password)
      exists.
    - The provisioner-script Vault token is available via the VAULT_TOKEN
      environment variable. It has only 'read' capability on the provisioner
      secret path. It must NEVER be the root token.
    - The target user exists in public.users (the FK on credentials.user_id
      enforces this; the script relies on the FK, not on a prior SELECT).

WHAT THIS SCRIPT DOES:
    1. Validate --user-id (canonical UUID).
    2. Read the provisioner DB password from Vault KV-v2.
    3. Prompt for the new user password via getpass (default) or generate
       one with --generate.
    4. Hash the password with Argon2id using the same parameters as
       app/api/routes/auth.py (the single source of truth):
           time_cost=2, memory_cost=19456, parallelism=1,
           hash_len=32, salt_len=16.
    5. INSERT INTO auth_private.credentials (user_id, password_hash)
       as securebiz_provisioner.
    6. Translate PostgreSQL errors:
         - unique_violation (23505)  -> credential already exists
         - foreign_key_violation (23503) -> user_id does not exist in public.users
         - insufficient_privilege (42501) -> role misconfigured
         - anything else -> generic failure, no SQL detail leaked.

WHAT THIS SCRIPT DOES NOT DO:
    - It does NOT create users in public.users.
    - It does NOT modify existing credentials (no --reset in v1).
    - It does NOT use the root token.
    - It does NOT log or display the password or the hash.

EXECUTION CONTEXT:
    This script MUST be executed INSIDE the securebiz-api container, because
    it uses the Docker-internal DNS names (vault:8200, db:5432).
    It is not designed to run on the Windows host directly.

    Copy it into the container, execute it, then remove it:

        docker cp scripts/provision_user.py securebiz-api:/tmp/provision_user.py
        docker exec -it -e VAULT_TOKEN=<provisioner-script-token> \
            -w /app securebiz-api python /tmp/provision_user.py \
            --user-id <uuid> [--email <email>] [--generate]
        docker exec securebiz-api rm -f /tmp/provision_user.py

USAGE (container):
    $env:VAULT_TOKEN = "<provisioner-script token>"
    python /tmp/provision_user.py --user-id <uuid> [--email <email>] [--generate]

    Without --generate, the script prompts twice (password + confirmation).
    With --generate, it prints the generated password ONCE, on stdout, with
    a clear warning. It is never stored.

ONE-SHOT PER CREDENTIAL:
    Re-running for the same user_id fails with unique_violation. Use a
    dedicated reset procedure (out of scope for v1) if a credential must
    be rotated.
================================================================================
"""

import argparse
import os
import sys
import getpass
import secrets
import uuid

import psycopg
from psycopg import sql
from argon2 import PasswordHasher
from argon2.exceptions import HashingError
import requests


VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
if not VAULT_TOKEN:
    sys.exit("VAULT_TOKEN is not set in the environment.")

VAULT_KV_PATH = "secret/data/securebiz/provisioner"
VAULT_PASSWORD_KEY = "db_password"

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "securebiz")
DB_USER = "securebiz_provisioner"

# Argon2id parameters MUST match app/api/routes/auth.py exactly.
# Reference: app/api/routes/auth.py lines 88-94 (single source of truth).
_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def vault_read(path: str) -> dict:
    r = requests.get(
        f"{VAULT_ADDR}/v1/{path}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        timeout=10,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Vault read failed: HTTP {r.status_code}")
    return r.json()["data"]["data"]


def parse_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise argparse.ArgumentTypeError(f"Invalid UUID: {value!r}")


def read_password(generate: bool) -> str:
    if generate:
        pwd = secrets.token_urlsafe(32)
        print("GENERATED_PASSWORD:", pwd)
        print("WARNING: this password is shown ONCE. Transmit it securely.")
        return pwd
    pwd1 = getpass.getpass("New password (hidden): ")
    if not pwd1:
        raise RuntimeError("empty password")
    pwd2 = getpass.getpass("Confirm password (hidden): ")
    if pwd1 != pwd2:
        raise RuntimeError("passwords do not match")
    return pwd1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision an Argon2id credential for a SecureBiz user."
    )
    parser.add_argument("--user-id", required=True, type=parse_uuid,
                        help="Canonical UUID of the user in public.users.")
    parser.add_argument("--email", default=None,
                        help="Optional email, used only for display.")
    parser.add_argument("--generate", action="store_true",
                        help="Generate a random password instead of prompting.")
    args = parser.parse_args()

    print(f"Target user_id: {args.user_id}")
    if args.email:
        print(f"Target email:   {args.email}")

    # Read DB password from Vault (read-only token)
    try:
        data = vault_read(VAULT_KV_PATH)
    except Exception as exc:
        sys.exit(f"FATAL: cannot read Vault secret: {exc}")
    if VAULT_PASSWORD_KEY not in data:
        sys.exit(f"FATAL: Vault secret missing key '{VAULT_PASSWORD_KEY}'")
    db_password = data[VAULT_PASSWORD_KEY]
    print("Read provisioner password from Vault (not displayed).")

    # Read the new password
    try:
        plain = read_password(args.generate)
    except RuntimeError as exc:
        sys.exit(f"FATAL: {exc}")

    # Hash with Argon2id
    try:
        hashed = _HASHER.hash(plain)
    except HashingError as exc:
        sys.exit(f"FATAL: Argon2id hashing failed: {type(exc).__name__}")
    finally:
        plain = None  # drop plaintext reference

    # INSERT as securebiz_provisioner
    print("Inserting credential as securebiz_provisioner...")
    try:
        with psycopg.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=db_password,
            connect_timeout=5,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL(
                        "INSERT INTO auth_private.credentials "
                        "(user_id, password_hash) VALUES (%s, %s)"
                    ),
                    (args.user_id, hashed),
                )
            conn.commit()
    except psycopg.errors.UniqueViolation:
        sys.exit("FAILED: a credential already exists for this user_id.")
    except psycopg.errors.ForeignKeyViolation:
        sys.exit("FAILED: user_id does not exist in public.users.")
    except psycopg.errors.InsufficientPrivilege:
        sys.exit("FAILED: securebiz_provisioner lacks INSERT on auth_private.credentials.")
    except psycopg.Error as exc:
        sys.exit(f"FAILED: database error: {type(exc).__name__}")

    print("Credential inserted successfully.")
    print("Done. The new user can authenticate via POST /auth/login.")


if __name__ == "__main__":
    main()

"""
scripts/set_provisioner_password.py
================================================================================
SecureBiz Lab - One-shot activation of securebiz_provisioner (fail-safe v2).

PRE-CONDITIONS (verified in step 4c.1):
    - auth_private.credentials has RLS disabled, no triggers, no policies.
    - securebiz_provisioner has USAGE on auth_private and INSERT on credentials.
    - The Vault secret secret/data/securebiz/provisioner (key db_password)
      has already been written by Invoke-Block4c-Vault.
    - The role is currently NOLOGIN.

WHAT THIS SCRIPT DOES:
    1. Read the provisioner password from Vault KV-v2.
    2. Prompt the operator for the securebiz_user password via getpass.
    3. Pre-flight:
         a. verify securebiz_user has the rights to ALTER ROLE;
         b. verify securebiz_provisioner exists and is currently NOLOGIN.
    4. ALTER ROLE securebiz_provisioner WITH LOGIN PASSWORD <pwd>.
    5. Verify SCRAM connection as securebiz_provisioner from the host,
       and that current_user is exactly securebiz_provisioner.
    6. Verify that SELECT on auth_private.credentials is denied.

FAIL-SAFE BEHAVIOR:
    Any exception during steps 5 or 6 (including unexpected Python errors,
    not only psycopg.Error) triggers rollback_to_nologin(). The rollback
    is verified by re-reading rolcanlogin. If the rollback cannot be
    confirmed, the script exits with an explicit FATAL message stating
    that the role state is unconfirmed.

    Limitation: if PostgreSQL becomes unreachable after ALTER ROLE, no
    script can guarantee the rollback. The script reports this explicitly.

WHAT THIS SCRIPT DOES NOT DO:
    - It does NOT generate a password.
    - It does NOT write the Vault secret.
    - It does NOT use the provisioner-script token.
    - It does NOT modify RLS, triggers, grants, or any table.

TOKEN USED:
    VAULT_TOKEN must be set in the environment. For this one-shot bootstrap,
    the root token is acceptable (administrative, non-recurring).
    The recurring script (provision_user.py, step 5) uses the dedicated
    provisioner-script token instead.

ONE-SHOT:
    Re-running rotates the PostgreSQL password on every run, and is refused
    by preflight_provisioner_state if the role is already LOGIN.
================================================================================
"""

import os
import sys
import getpass

import psycopg
from psycopg import sql
import requests


VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
if not VAULT_TOKEN:
    sys.exit("VAULT_TOKEN is not set in the environment.")

VAULT_KV_PATH = "secret/data/securebiz/provisioner"

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "securebiz")
DB_ADMIN_USER = "securebiz_user"

PROVISIONER_ROLE = "securebiz_provisioner"
PROVISIONER_PASSWORD_KEY = "db_password"


def vault_read(path: str) -> dict:
    """Read a KV-v2 secret from Vault. Returns the inner data dict."""
    r = requests.get(
        f"{VAULT_ADDR}/v1/{path}",
        headers={"X-Vault-Token": VAULT_TOKEN},
        timeout=10,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Vault read failed: HTTP {r.status_code}")
    return r.json()["data"]["data"]


def admin_connect(admin_password: str):
    """Open an administrative connection as securebiz_user."""
    return psycopg.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_ADMIN_USER, password=admin_password,
        connect_timeout=5,
    )


def preflight_admin_rights(conn) -> None:
    """Verify securebiz_user can ALTER the provisioner role."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolcreaterole FROM pg_roles WHERE rolname = %s",
            (DB_ADMIN_USER,),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError(f"Role {DB_ADMIN_USER} not found in pg_roles")
    is_super, can_createrole = row
    if not (is_super or can_createrole):
        raise RuntimeError(
            f"{DB_ADMIN_USER} lacks CREATEROLE and is not superuser; cannot ALTER ROLE"
        )


def preflight_provisioner_state(conn) -> None:
    """Verify the target role exists and is currently NOLOGIN."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s",
            (PROVISIONER_ROLE,),
        )
        row = cur.fetchone()
    if row is None:
        raise RuntimeError(f"Target role {PROVISIONER_ROLE} does not exist")
    if row[0] is not False:
        raise RuntimeError(
            f"Target role {PROVISIONER_ROLE} is already LOGIN; "
            "refusing unexpected reactivation"
        )


def rollback_to_nologin(admin_password: str) -> bool:
    """Attempt to revert the role to NOLOGIN. Returns True on confirmed rollback."""
    print("ROLLBACK: reverting securebiz_provisioner to NOLOGIN...")
    try:
        with admin_connect(admin_password) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("ALTER ROLE {} WITH NOLOGIN").format(
                        sql.Identifier(PROVISIONER_ROLE)
                    )
                )
            conn.commit()
    except psycopg.Error as exc:
        print(f"ROLLBACK FAILED: {type(exc).__name__}. Manual intervention required.")
        return False

    try:
        with admin_connect(admin_password) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT rolcanlogin FROM pg_roles WHERE rolname = %s",
                    (PROVISIONER_ROLE,),
                )
                row = cur.fetchone()
    except psycopg.Error as exc:
        print(f"ROLLBACK VERIFICATION FAILED: {type(exc).__name__}. Manual intervention required.")
        return False

    if row is None or row[0] is not False:
        print("ROLLBACK VERIFICATION FAILED: role is not NOLOGIN. Manual intervention required.")
        return False

    print("ROLLBACK OK: securebiz_provisioner is back to NOLOGIN.")
    return True


def main() -> None:
    # Step 1: read the provisioner password from Vault
    try:
        data = vault_read(VAULT_KV_PATH)
    except Exception as exc:
        sys.exit(f"FATAL: cannot read Vault secret at {VAULT_KV_PATH}: {exc}")
    if PROVISIONER_PASSWORD_KEY not in data:
        sys.exit(f"FATAL: Vault secret missing key '{PROVISIONER_PASSWORD_KEY}'")
    provisioner_password = data[PROVISIONER_PASSWORD_KEY]
    print(f"Read provisioner password from Vault ({VAULT_KV_PATH}, key {PROVISIONER_PASSWORD_KEY}). Not displayed.")

    # Step 2: prompt for securebiz_user password
    admin_password = getpass.getpass(
        f"Password for {DB_ADMIN_USER} (bootstrap, hidden): "
    )
    if not admin_password:
        sys.exit("FATAL: empty password.")

    # Step 3: pre-flight administrative rights and target role state
    print("Pre-flight: verifying administrative rights and target role state...")
    try:
        with admin_connect(admin_password) as conn:
            preflight_admin_rights(conn)
            preflight_provisioner_state(conn)
    except psycopg.Error as exc:
        sys.exit(f"FATAL: admin connection failed: {type(exc).__name__}")
    except RuntimeError as exc:
        sys.exit(f"FATAL: pre-flight check failed: {exc}")
    print("Pre-flight: OK.")

    # Step 4: ALTER ROLE ... WITH LOGIN PASSWORD
    print(f"Executing ALTER ROLE {PROVISIONER_ROLE} WITH LOGIN PASSWORD ...")
    try:
        with admin_connect(admin_password) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(
                        sql.Identifier(PROVISIONER_ROLE),
                        sql.Literal(provisioner_password),
                    )
                )
            conn.commit()
    except psycopg.Error as exc:
        sys.exit(f"FATAL: ALTER ROLE failed: {type(exc).__name__}")
    print(f"ALTER ROLE {PROVISIONER_ROLE} WITH LOGIN PASSWORD succeeded.")

    # From here on, the role is LOGIN.
    # Every verification failure must trigger rollback.

    try:
        # Step 5: verify SCRAM connection
        print("Verifying connection as securebiz_provisioner from host (SCRAM-SHA-256)...")

        with psycopg.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=PROVISIONER_ROLE,
            password=provisioner_password,
            connect_timeout=5,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user, inet_client_addr()")
                user, ip = cur.fetchone()

        if user != PROVISIONER_ROLE:
            raise RuntimeError("Connected PostgreSQL role does not match expected role")

        print(f"Connection as {user} succeeded (client IP: {ip}).")

        # Step 6: verify SELECT is denied
        print("Verifying that SELECT on auth_private.credentials is denied...")

        try:
            with psycopg.connect(
                host=DB_HOST,
                port=DB_PORT,
                dbname=DB_NAME,
                user=PROVISIONER_ROLE,
                password=provisioner_password,
                connect_timeout=5,
            ) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT user_id FROM auth_private.credentials LIMIT 1"
                    )
        except psycopg.errors.InsufficientPrivilege:
            print(
                "SELECT on auth_private.credentials correctly denied "
                "(InsufficientPrivilege)."
            )
        else:
            raise RuntimeError(
                "SECURITY: SELECT on auth_private.credentials was not denied"
            )

    except Exception as exc:
        print(
            f"VERIFICATION FAILED: {type(exc).__name__}. "
            "Starting automatic rollback."
        )

        if not rollback_to_nologin(admin_password):
            sys.exit(
                "FATAL: rollback could not be confirmed. "
                "The role may still have LOGIN. Manual intervention required."
            )

        sys.exit(
            "FAILED: verification did not pass. "
            "Rollback confirmed: securebiz_provisioner is NOLOGIN."
        )

    print("Done. Provisioner role is active and correctly restricted.")


if __name__ == "__main__":
    main()

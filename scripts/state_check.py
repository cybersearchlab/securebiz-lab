"""
scripts/state_check.py
================================================================================
SecureBiz Lab - One-shot state verification for new agents.

v4 (2026-11-13): Priority 9 extension.
    - Added: refresh_tokens, get_user_status ACL + behavior,
      credentials count, provisioner role checks.
    - Replaced hardcoded public key constant with dynamic Vault read.
    - Centralized _admin_ready() for consistent degraded mode.
    - Strict Base64 decoding (validate=True, 32-byte check).

READ-ONLY with one transactional exception:
    - check_public_key, check_test_data, check_auth_session_refresh_tokens,
      check_get_user_status_acl, check_credentials_count,
      check_provisioner_role, check_vault_sign: pure read-only.
    - check_full_flow: calls install_context() which writes
      transaction_context and used_jti, then ROLLBACK. No persisted change.

Run inside the API container:
    docker compose exec api python scripts/state_check.py
================================================================================
"""

import base64
import binascii
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
import uuid

import psycopg

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200").rstrip("/")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
KEY_NAME = os.getenv("VAULT_TRANSIT_KEY", "securebiz-context")

TEST_USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
TEST_ORG_ID = "1a40e607-b991-4b06-ad1f-13106d65b12a"

ADMIN_USER = os.getenv("DB_ADMIN_USER")
ADMIN_PASSWORD = os.getenv("DB_ADMIN_PASSWORD")

results = []


def record(section, status, detail=""):
    results.append((section, status, detail))


def safe(section, fn):
    try:
        fn()
    except Exception as exc:
        record(section, "FAIL", str(exc)[:200])


def _admin_ready():
    return bool(ADMIN_USER and ADMIN_PASSWORD)



def _safe_urlopen(req, timeout=5):
    """
    Open a request only against the internal Docker Vault endpoint.

    SECURITY:
    - HTTP only (internal development Docker network).
    - Exact authority: vault:8200.
    - No userinfo, alternate host, or alternate port.
    - No query string or fragment.
    """
    url = req.full_url if hasattr(req, "full_url") else str(req)
    parsed = urlparse(url)

    if parsed.scheme != "http":
        raise ValueError("Blocked Vault URL scheme")

    if parsed.netloc != "vault:8200":
        raise ValueError("Blocked Vault URL authority")

    if parsed.hostname != "vault":
        raise ValueError("Blocked Vault URL host")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid Vault URL port") from exc

    if port != 8200:
        raise ValueError("Blocked Vault URL port")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Vault URL userinfo is forbidden")

    if parsed.query or parsed.fragment:
        raise ValueError("Vault URL query and fragment are forbidden")

    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310 - Exact internal Vault authority validated above.
def check_env():
    record("env: VAULT_ADDR", "OK", VAULT_ADDR)
    record("env: VAULT_TOKEN", "OK" if VAULT_TOKEN else "FAIL",
           "set (len=%d)" % len(VAULT_TOKEN) if VAULT_TOKEN else "missing")
    record("env: VAULT_TRANSIT_KEY", "OK", KEY_NAME)
    record("env: DB_ADMIN_USER", "OK" if ADMIN_USER else "SKIP",
           "present" if ADMIN_USER else "missing")
    record("env: DB_ADMIN_PASSWORD", "OK" if ADMIN_PASSWORD else "SKIP",
           "present" if ADMIN_PASSWORD else "missing")


def _connect_admin():
    if not _admin_ready():
        raise RuntimeError("admin credentials not configured")
    return psycopg.connect(
        host=os.environ["DB_HOST"], port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"], user=ADMIN_USER,
        password=ADMIN_PASSWORD, connect_timeout=3,
    )


def check_db_structure():
    if not _admin_ready():
        record("db: tables", "SKIP", "admin credentials missing")
        record("db: functions", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_schema IN
                    ('public','auth_private','auth_security','auth_session')
                  AND table_type='BASE TABLE'
            """)
            tables = {(r[0], r[1]) for r in cur.fetchall()}
        expected = {
            ("auth_private", "credentials"),
            ("auth_security", "public_keys"),
            ("auth_security", "transaction_context"),
            ("auth_security", "used_jti"),
            ("auth_session", "refresh_tokens"),
            ("public", "users"),
            ("public", "organizations"),
            ("public", "memberships"),
            ("public", "roles"),
            ("public", "permissions"),
            ("public", "membership_roles"),
            ("public", "role_permissions"),
        }
        missing = expected - tables
        if missing:
            record("db: tables", "FAIL", "missing: %s" % sorted(missing))
        else:
            record("db: tables", "OK", "%d expected tables present" % len(expected))

        with conn.cursor() as cur:
            cur.execute("""
                SELECT routine_schema || '.' || routine_name
                FROM information_schema.routines
                WHERE routine_schema IN
                    ('auth_security', 'auth_session', 'auth_private')
            """)
            fns = {r[0] for r in cur.fetchall()}
        required = {
            "auth_security.securebiz_install_context",
            "auth_security.securebiz_get_context",
            "auth_security.securebiz_cleanup_context",
            "auth_private.authenticate",
            "auth_session.get_user_status",
        }
        missing = required - fns
        if missing:
            record("db: functions", "FAIL", "missing: %s" % sorted(missing))
        else:
            record("db: functions", "OK", "all required functions present")
    finally:
        conn.close()


def check_public_key():
    if not VAULT_TOKEN:
        record("db: public_key", "SKIP", "no vault token")
        return
    if not _admin_ready():
        record("db: public_key", "SKIP", "admin credentials missing")
        return

    try:
        req = urllib.request.Request(
            "%s/v1/transit/keys/%s" % (VAULT_ADDR, KEY_NAME),
            headers={"X-Vault-Token": VAULT_TOKEN},
        )
        with _safe_urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        keys = data["data"]["keys"]
        latest_ver = str(max(int(k) for k in keys))
        vault_key_b64 = keys[latest_ver]["public_key"]
        try:
            vault_key_bytes = base64.b64decode(vault_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            record("db: public_key", "FAIL",
                   "Vault key not valid base64: %s" % exc)
            return
        if len(vault_key_bytes) != 32:
            record("db: public_key", "FAIL",
                   "Vault key is %d bytes, expected 32" % len(vault_key_bytes))
            return
        vault_key_hex = vault_key_bytes.hex()
    except Exception as exc:
        record("db: public_key", "FAIL", "vault read: %s" % exc)
        return

    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT encode(public_key, 'hex'), revoked_at
                FROM auth_security.public_keys
                WHERE kid = %s
            """, (KEY_NAME,))
            row = cur.fetchone()
        if not row:
            record("db: public_key", "FAIL", "no row for kid=%s" % KEY_NAME)
            return
        pg_key_hex, revoked_at = row
        if revoked_at is not None:
            record("db: public_key", "FAIL",
                   "key %s is REVOKED" % KEY_NAME)
            return
        if pg_key_hex != vault_key_hex:
            record("db: public_key", "WARN",
                   "DIVERGENCE Vault=%s... PG=%s..."
                   % (vault_key_hex[:16], pg_key_hex[:16]))
            return
        record("db: public_key", "OK",
               "Vault and PG match (%s...)" % vault_key_hex[:16])
    finally:
        conn.close()


def check_test_data():
    if not _admin_ready():
        record("db: test_data", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.status, m.status, o.status
                FROM public.users u
                JOIN public.memberships m ON m.user_id = u.id
                JOIN public.organizations o ON o.id = m.organization_id
                WHERE u.id = %s AND m.organization_id = %s
            """, (TEST_USER_ID, TEST_ORG_ID))
            row = cur.fetchone()
        if not row:
            record("db: test_data", "FAIL", "not linked or missing")
            return
        u, m, o = row
        if (u, m, o) != ("active", "active", "active"):
            record("db: test_data", "FAIL",
                   "statuses user=%s mem=%s org=%s" % (u, m, o))
            return
        record("db: test_data", "OK", "user/membership/org all active")
    finally:
        conn.close()


def check_auth_session_refresh_tokens():
    if not _admin_ready():
        record("db: refresh_tokens", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    count(*) AS total,
                    count(*) FILTER (
                        WHERE revoked_at IS NULL
                          AND expires_at > clock_timestamp()
                    ) AS active
                FROM auth_session.refresh_tokens
            """)
            total, active = cur.fetchone()
        record("db: refresh_tokens", "OK",
               "total=%d active=%d" % (total, active))
        if active > 0:
            record("db: refresh_tokens_active", "WARN",
                   "%d active tokens (expected 0 after tests)" % active)
    finally:
        conn.close()


def check_get_user_status_acl():
    if not _admin_ready():
        record("db: get_user_status_acl", "SKIP", "admin credentials missing")
        record("db: get_user_status_behavior", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT has_function_privilege('securebiz_auth',
                    'auth_session.get_user_status(uuid)', 'EXECUTE') AS auth_can,
                       has_function_privilege('securebiz_app',
                    'auth_session.get_user_status(uuid)', 'EXECUTE') AS app_can
            """)
            auth_can, app_can = cur.fetchone()
        if not auth_can:
            record("db: get_user_status_acl", "FAIL",
                   "securebiz_auth cannot EXECUTE")
        elif app_can:
            record("db: get_user_status_acl", "FAIL",
                   "securebiz_app should NOT EXECUTE")
        else:
            record("db: get_user_status_acl", "OK",
                   "auth=EXECUTE, app=NO-EXECUTE")

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    auth_session.get_user_status(NULL::uuid),
                    auth_session.get_user_status(
                        '00000000-0000-0000-0000-000000000000'::uuid
                    )
            """)
            null_status, unknown_status = cur.fetchone()
        if null_status is not None or unknown_status is not None:
            record("db: get_user_status_behavior", "FAIL",
                   "NULL or unknown UUID did not return NULL")
        else:
            record("db: get_user_status_behavior", "OK",
                   "NULL and unknown UUID both return NULL")
    finally:
        conn.close()


def check_credentials_count():
    if not _admin_ready():
        record("db: credentials", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM auth_private.credentials")
            (count,) = cur.fetchone()
        record("db: credentials", "OK", "%d row(s)" % count)
    finally:
        conn.close()


def check_provisioner_role():
    if not _admin_ready():
        record("db: provisioner_role", "SKIP", "admin credentials missing")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                       rolreplication, rolbypassrls
                FROM pg_roles WHERE rolname = 'securebiz_provisioner'
            """)
            row = cur.fetchone()
        if not row:
            record("db: provisioner_role", "FAIL", "role missing")
            return
        can_login, is_super, can_createdb, can_createrole, can_repl, bypass_rls = row
        if not can_login:
            record("db: provisioner_role", "FAIL", "role is NOLOGIN")
            return
        if is_super or bypass_rls:
            record("db: provisioner_role", "FAIL",
                   "role is superuser or BYPASSRLS")
            return
        if can_createdb or can_createrole or can_repl:
            record("db: provisioner_role", "FAIL",
                   "role has CREATEDB/CREATEROLE/REPLICATION")
            return

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    has_schema_privilege('securebiz_provisioner',
                        'auth_private', 'USAGE') AS usage,
                    has_schema_privilege('securebiz_provisioner',
                        'auth_private', 'CREATE') AS create
            """)
            usage, create = cur.fetchone()
        if not usage:
            record("db: provisioner_role", "FAIL",
                   "no USAGE on auth_private")
            return
        if create:
            record("db: provisioner_role", "FAIL",
                   "has CREATE on auth_private (should not)")
            return

        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'INSERT') AS ins,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'SELECT') AS sel,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'UPDATE') AS upd,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'DELETE') AS del,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'TRUNCATE') AS trunc,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'REFERENCES') AS ref,
                    has_table_privilege('securebiz_provisioner',
                        'auth_private.credentials', 'TRIGGER') AS trig
            """)
            ins, sel, upd, dele, trunc, ref, trig = cur.fetchone()
        if not ins:
            record("db: provisioner_role", "FAIL",
                   "no INSERT on credentials")
            return
        if sel or upd or dele or trunc or ref or trig:
            record("db: provisioner_role", "FAIL",
                   "unexpected table privileges on credentials")
            return

        with conn.cursor() as cur:
            cur.execute("""
                SELECT count(*) FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.member
                WHERE r.rolname = 'securebiz_provisioner'
            """)
            (memberships,) = cur.fetchone()
        if memberships > 0:
            record("db: provisioner_role", "FAIL",
                   "%d role memberships (expected 0)" % memberships)
            return

        record("db: provisioner_role", "OK",
               "LOGIN, INSERT only, no memberships, no CREATE/USAGE on schema")
    finally:
        conn.close()


def _sign_payload(payload_json):
    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        "%s/v1/transit/sign/%s" % (VAULT_ADDR, KEY_NAME),
        data=json.dumps({"input": payload_b64}).encode("utf-8"),
        method="POST",
        headers={"X-Vault-Token": VAULT_TOKEN,
                 "Content-Type": "application/json"},
    )
    with _safe_urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    sig = data["data"]["signature"]
    if not sig.startswith("vault:v"):
        raise RuntimeError("unexpected signature prefix")
    _, ver, b64 = sig.split(":", 2)
    sig_bytes = base64.b64decode(b64)
    if len(sig_bytes) != 64:
        raise RuntimeError("signature %d bytes, expected 64" % len(sig_bytes))
    return sig_bytes, ver, data["data"].get("key_version")


def check_vault_sign():
    if not VAULT_TOKEN:
        record("vault: sign", "FAIL", "no token")
        return
    now = int(time.time())
    payload = {
        "iss": "securebiz-api", "aud": "securebiz-postgres",
        "sub": TEST_USER_ID, "org": TEST_ORG_ID,
        "jti": str(uuid.uuid4()), "iat": now, "exp": now + 30,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    try:
        sig_bytes, ver, kv = _sign_payload(payload_json)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        record("vault: sign", "FAIL", "HTTP %s: %s" % (e.code, body))
        return
    except urllib.error.URLError as e:
        record("vault: sign", "FAIL", "unreachable: %s" % e.reason)
        return
    record("vault: sign", "OK",
           "64-byte Ed25519, key_version=%s, vault_version=%s" % (kv, ver))


def check_full_flow():
    if not VAULT_TOKEN:
        record("e2e: install_context", "FAIL", "no vault token")
        return
    if not _admin_ready():
        record("e2e: install_context", "SKIP", "admin credentials missing")
        return

    conn = _connect_admin()
    conn.autocommit = False
    try:
        now = int(time.time())
        payload = {
            "iss": "securebiz-api", "aud": "securebiz-postgres",
            "sub": TEST_USER_ID, "org": TEST_ORG_ID,
            "jti": str(uuid.uuid4()), "iat": now, "exp": now + 30,
        }
        payload_json = json.dumps(payload, separators=(",", ":"),
                                  sort_keys=True)
        sig_bytes, _, _ = _sign_payload(payload_json)

        with conn.cursor() as cur:
            cur.execute(
                "SELECT auth_security.securebiz_install_context(%s,%s,%s)",
                (payload_json, sig_bytes, KEY_NAME),
            )
            ok = cur.fetchone()[0]
            cur.execute(
                "SELECT auth_security.securebiz_get_context('user_id')")
            got_user = cur.fetchone()[0]
            cur.execute(
                "SELECT auth_security.securebiz_get_context('organization_id')")
            got_org = cur.fetchone()[0]

        if not ok:
            record("e2e: install_context", "FAIL", "returned False")
            return
        if str(got_user) != TEST_USER_ID or str(got_org) != TEST_ORG_ID:
            record("e2e: install_context", "FAIL",
                   "context mismatch: %s / %s" % (got_user, got_org))
            return
        record("e2e: install_context", "OK",
               "install + get + rollback successful")
    except urllib.error.HTTPError as e:
        record("e2e: install_context", "FAIL", "vault HTTP %s" % e.code)
    except Exception as exc:
        record("e2e: install_context", "FAIL", str(exc)[:200])
    finally:
        try:
            conn.rollback()
        finally:
            conn.close()


def main():
    print("=" * 72)
    print(" SecureBiz Lab - state_check.py  (v4, Priority 9)")
    print("=" * 72)

    for name, fn in [
        ("env", check_env),
        ("db: structure", check_db_structure),
        ("db: public_key", check_public_key),
        ("db: test_data", check_test_data),
        ("db: refresh_tokens", check_auth_session_refresh_tokens),
        ("db: get_user_status_acl", check_get_user_status_acl),
        ("db: credentials", check_credentials_count),
        ("db: provisioner_role", check_provisioner_role),
        ("vault: sign", check_vault_sign),
        ("e2e: install_context", check_full_flow),
    ]:
        safe(name, fn)

    print()
    for section, status, detail in results:
        print("[%-4s] %-30s %s" % (status, section, detail))

    fails = [r for r in results if r[1] == "FAIL"]
    warns = [r for r in results if r[1] == "WARN"]
    skips = [r for r in results if r[1] == "SKIP"]
    print()
    if fails:
        print("RESULT: %d FAILED - investigate." % len(fails))
        sys.exit(1)
    if warns:
        print("RESULT: %d WARN, %d OK, %d SKIP - review warnings."
              % (len(warns), len(results) - len(warns) - len(skips), len(skips)))
        sys.exit(0)
    if skips:
        print("RESULT: %d SKIP (admin creds absent), %d OK - partial."
              % (len(skips), len(results) - len(skips)))
        sys.exit(0)
    print("RESULT: all checks passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
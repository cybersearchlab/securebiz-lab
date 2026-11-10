"""
scripts/state_check.py
================================================================================
SecureBiz Lab - One-shot state verification for new agents.

v3 (2026-11-10): Ed25519 fix (no hash_algorithm/prehashed), admin role
for structural checks, degraded mode when admin credentials absent.

Run inside the API container:
    docker compose exec api python scripts/state_check.py
================================================================================
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

import psycopg

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200").rstrip("/")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
KEY_NAME = os.getenv("VAULT_TRANSIT_KEY", "securebiz-context")

EXPECTED_PUBKEY_HEX = (
    "ccc071be49abbcdef22b541bb7ad984de"
    "1364730814dde3d54b9844a370a4e89"
)

TEST_USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
TEST_ORG_ID = "1a40e607-b991-4b06-ad1f-13106d65b12a"

# Optional admin credentials - if absent, structural checks are SKIPPED
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


def check_env():
    record("env: VAULT_ADDR", "OK", VAULT_ADDR)
    record("env: VAULT_TOKEN", "OK" if VAULT_TOKEN else "FAIL",
           "set (len=%d)" % len(VAULT_TOKEN) if VAULT_TOKEN else "missing")
    record("env: VAULT_TRANSIT_KEY", "OK", KEY_NAME)
    record("env: DB_ADMIN_USER", "OK" if ADMIN_USER else "SKIP",
           "present" if ADMIN_USER else
           "absent (set DB_ADMIN_USER/DB_ADMIN_PASSWORD to enable structural checks)")


def _connect_admin():
    if not ADMIN_USER or not ADMIN_PASSWORD:
        raise RuntimeError("admin credentials not configured")
    return psycopg.connect(
        host=os.environ["DB_HOST"], port=os.environ["DB_PORT"],
        dbname=os.environ["DB_NAME"], user=ADMIN_USER,
        password=ADMIN_PASSWORD, connect_timeout=3,
    )


def check_db_structure():
    if not ADMIN_USER:
        record("db: tables", "SKIP", "admin role required")
        record("db: functions", "SKIP", "admin role required")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_schema, table_name
                FROM information_schema.tables
                WHERE table_schema IN ('public','auth_private','auth_security')
                  AND table_type='BASE TABLE'
            """)
            tables = {(r[0], r[1]) for r in cur.fetchall()}
        expected = {
            ("auth_private", "credentials"),
            ("auth_security", "public_keys"),
            ("auth_security", "transaction_context"),
            ("auth_security", "used_jti"),
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
                SELECT routine_name
                FROM information_schema.routines
                WHERE routine_schema='auth_security'
            """)
            fns = {r[0] for r in cur.fetchall()}
        required = {"securebiz_install_context", "securebiz_get_context",
                    "securebiz_cleanup_context"}
        missing = required - fns
        if missing:
            record("db: functions", "FAIL", "missing: %s" % sorted(missing))
        else:
            record("db: functions", "OK", "install/get/cleanup present")
    finally:
        conn.close()


def check_public_key():
    if not ADMIN_USER:
        record("db: public_key", "SKIP", "admin role required")
        return
    conn = _connect_admin()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT kid, encode(public_key,'hex'), revoked_at
                FROM auth_security.public_keys
                WHERE kid = %s
            """, (KEY_NAME,))
            row = cur.fetchone()
        if not row:
            record("db: public_key", "FAIL", "no row for kid=%s" % KEY_NAME)
            return
        kid, hex_key, revoked_at = row
        if revoked_at is not None:
            record("db: public_key", "FAIL", "%s revoked at %s" % (kid, revoked_at))
            return
        if hex_key != EXPECTED_PUBKEY_HEX:
            record("db: public_key", "FAIL", "pubkey hex mismatch")
            return
        record("db: public_key", "OK", "%s active, hex OK" % kid)
    finally:
        conn.close()


def check_test_data():
    if not ADMIN_USER:
        record("db: test_data", "SKIP", "admin role required")
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


def _sign_payload(payload_json):
    """Sign payload_json bytes with Vault Transit Ed25519. No hash_algorithm."""
    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")
    req = urllib.request.Request(
        "%s/v1/transit/sign/%s" % (VAULT_ADDR, KEY_NAME),
        data=json.dumps({"input": payload_b64}).encode("utf-8"),
        method="POST",
        headers={"X-Vault-Token": VAULT_TOKEN,
                 "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
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
    if not ADMIN_USER:
        record("e2e: install_context", "SKIP", "admin role required")
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
    print(" SecureBiz Lab - state_check.py  (handover v2, section 15)")
    print("=" * 72)

    for name, fn in [
        ("env", check_env),
        ("db: structure", check_db_structure),
        ("db: public_key", check_public_key),
        ("db: test_data", check_test_data),
        ("vault: sign", check_vault_sign),
        ("e2e: install_context", check_full_flow),
    ]:
        safe(name, fn)

    print()
    for section, status, detail in results:
        print("[%-4s] %-28s %s" % (status, section, detail))

    fails = [r for r in results if r[1] == "FAIL"]
    skips = [r for r in results if r[1] == "SKIP"]
    print()
    if fails:
        print("RESULT: %d FAILED - investigate before coding." % len(fails))
        sys.exit(1)
    if skips:
        print("RESULT: %d skipped (admin creds absent), %d OK - "
              "partial validation only." % (len(skips),
              len(results) - len(skips)))
        sys.exit(0)
    print("RESULT: all checks passed. Proceed to section 15.10 (next actions).")


if __name__ == "__main__":
    main()

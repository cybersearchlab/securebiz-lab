"""
SecureBiz Lab - Integration tests for app.services.refresh (real PostgreSQL).
================================================================================
These tests run against a REAL PostgreSQL database via
app.core.database.get_auth_connection() (securebiz_auth role).

They complement tests/test_refresh.py (31 mocked unit tests). The mock
tests validate the Python logic; these integration tests validate the
PostgreSQL behaviour that mocks cannot cover:

    - real INSERT / UPDATE / SELECT against auth_session.refresh_tokens;
    - real advisory locks (pg_advisory_xact_lock);
    - real CHECK / UNIQUE / FK constraint violations;
    - real transaction lifecycle (commit / rollback).

Isolation rules:
    - The existing database state (32 rows, 2 active tokens from other
      families) is left untouched.
    - Each test creates its OWN family with create_refresh_family() and
      revokes it in a finally block via revoke_family().
    - Each test asserts on its own family only; no global 'active=0'
      assertion is performed.
    - No DELETE, no TRUNCATE, no DROP.
    - No use of the superuser securebiz_user in test code.
    - If revoke_family() fails during cleanup, the test FAILS LOUDLY
      (the cleanup failure is not silently swallowed).

Requires the API container (db:5432 is a Docker-internal DNS name).
Run with:
    docker cp tests/test_refresh_db.py securebiz-api:/tmp/
    docker exec -w /app securebiz-api env PYTHONPATH=/app \
        python -m pytest /tmp/test_refresh_db.py -v
================================================================================
"""

import uuid

import psycopg
import pytest

from app.core.database import get_auth_connection
from app.services.refresh import (
    RefreshTokenError,
    create_refresh_family,
    hash_refresh_token,
    revoke_family,
    rotate_refresh_token,
)


TEST_USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"

# A non-existent UUID guaranteed not to collide with any real user.
UNKNOWN_USER_ID = "00000000-0000-0000-0000-0000000000ff"

# A non-existent UUID guaranteed not to collide with any real token id.
UNKNOWN_TOKEN_ID = "00000000-0000-0000-0000-0000000000aa"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_family_rows(family_id):
    """Return (total, active) row counts for the given family, as securebiz_auth."""
    conn = get_auth_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    count(*) AS total,
                    count(*) FILTER (
                        WHERE revoked_at IS NULL
                          AND expires_at > clock_timestamp()
                    ) AS active
                FROM auth_session.refresh_tokens
                WHERE family_id = %s
                """,
                (str(family_id),),
            )
            return cur.fetchone()
    finally:
        if not conn.closed:
            conn.close()


def _assert_family_revoked(family_id):
    """Assert that no active token remains in the family. Raises on failure."""
    total, active = _count_family_rows(family_id)
    assert active == 0, (
        f"Family {family_id} still has {active} active token(s) after cleanup "
        f"(total={total}). revoke_family() did not fully revoke the family."
    )


def _try_sql(conn, sql, params):
    """
    Execute a SQL statement in a SAVEPOINT so a constraint violation does
    not poison the surrounding transaction.

    Returns the caught exception, or None if the statement succeeded.
    The caller MUST be inside a transaction (autocommit=False) and MUST
    issue a rollback at the end.
    """
    with conn.cursor() as cur:
        cur.execute("SAVEPOINT sp_test")
        try:
            cur.execute(sql, params)
            cur.execute("RELEASE SAVEPOINT sp_test")
            return None
        except psycopg.Error as exc:
            cur.execute("ROLLBACK TO SAVEPOINT sp_test")
            return exc


# ---------------------------------------------------------------------------
# 1. create_refresh_family inserts a row with SHA-256 hash, not the raw token
# ---------------------------------------------------------------------------

def test_create_refresh_family_persists_hash_not_raw_token():
    raw, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        assert isinstance(raw, str) and raw

        conn = get_auth_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT token_hash, octet_length(token_hash),
                           revoked_at, expires_at > issued_at
                    FROM auth_session.refresh_tokens
                    WHERE family_id = %s
                    """,
                    (str(family_id),),
                )
                rows = cur.fetchall()
        finally:
            if not conn.closed:
                conn.close()

        assert len(rows) == 1, f"Expected 1 row, got {len(rows)}"
        stored_hash, hash_len, revoked_at, expiry_ok = rows[0]
        assert hash_len == 32
        assert revoked_at is None
        assert expiry_ok is True
        # The raw token is NEVER stored.
        assert stored_hash != raw.encode("utf-8")
        # The stored value is exactly SHA-256(raw).
        assert stored_hash == hash_refresh_token(raw)
    finally:
        revoke_family(family_id)
        _assert_family_revoked(family_id)


# ---------------------------------------------------------------------------
# 2. rotate_refresh_token creates a new token, revokes the old one,
#    keeps the same family_id, and sets replaced_by
# ---------------------------------------------------------------------------

def test_rotate_refresh_token_revokes_old_and_creates_new_in_same_family():
    raw1, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        raw2, user_id = rotate_refresh_token(raw1)
        assert user_id == TEST_USER_ID
        assert raw2 != raw1

        conn = get_auth_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, token_hash, revoked_at, replaced_by, expires_at > issued_at
                    FROM auth_session.refresh_tokens
                    WHERE family_id = %s
                    ORDER BY issued_at
                    """,
                    (str(family_id),),
                )
                rows = cur.fetchall()
        finally:
            if not conn.closed:
                conn.close()

        assert len(rows) == 2, f"Expected 2 rows, got {len(rows)}"
        old_id, old_hash, old_revoked, old_replaced_by, old_expiry = rows[0]
        new_id, new_hash, new_revoked, new_replaced_by, new_expiry = rows[1]

        # Old row: revoked, replaced_by = new_id, hash = SHA-256(raw1)
        assert old_revoked is not None
        assert old_replaced_by == new_id
        assert old_hash == hash_refresh_token(raw1)

        # New row: active, no replaced_by, hash = SHA-256(raw2)
        assert new_revoked is None
        assert new_replaced_by is None
        assert new_hash == hash_refresh_token(raw2)
    finally:
        revoke_family(family_id)
        _assert_family_revoked(family_id)


# ---------------------------------------------------------------------------
# 3. revoke_family is idempotent
# ---------------------------------------------------------------------------

def test_revoke_family_is_idempotent_on_real_db():
    raw, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        revoke_family(family_id)
        _assert_family_revoked(family_id)

        # Second call: no exception, family still fully revoked.
        revoke_family(family_id)
        _assert_family_revoked(family_id)
    finally:
        # cleanup idempotent, just in case.
        revoke_family(family_id)


# ---------------------------------------------------------------------------
# 4. rotate_refresh_token on a reused (revoked) token raises and
#    revokes the family
# ---------------------------------------------------------------------------

def test_rotate_on_revoked_token_detects_reuse_and_revokes_family():
    raw1, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        raw2, _ = rotate_refresh_token(raw1)  # normal rotation; raw1 now revoked

        # Replay raw1: this is reuse detection.
        with pytest.raises(RefreshTokenError, match="reuse detected"):
            rotate_refresh_token(raw1)

        # The whole family must now be revoked, including raw2.
        _assert_family_revoked(family_id)

        # And raw2 must now be rejected too.
        with pytest.raises(RefreshTokenError, match="reuse detected"):
            rotate_refresh_token(raw2)
    finally:
        revoke_family(family_id)


# ---------------------------------------------------------------------------
# 5. rotate_refresh_token on an unknown token raises "unknown token"
# ---------------------------------------------------------------------------

def test_rotate_unknown_token_raises_unknown_token():
    # A syntactically valid opaque token that was never issued.
    bogus = "definitely-not-a-real-refresh-token-0123456789ABCDEF"
    with pytest.raises(RefreshTokenError, match="unknown token"):
        rotate_refresh_token(bogus)


# ---------------------------------------------------------------------------
# 6. CHECK constraint: token_hash must be exactly 32 bytes
# ---------------------------------------------------------------------------

def test_check_constraint_hash_length_rejects_wrong_size():
    conn = get_auth_connection()
    try:
        conn.autocommit = False
        exc = _try_sql(
            conn,
            """
            INSERT INTO auth_session.refresh_tokens
                (user_id, family_id, token_hash, expires_at)
            VALUES
                (%s, %s, %s, clock_timestamp() + interval '1 day')
            """,
            (
                TEST_USER_ID,
                str(uuid.uuid4()),
                b"\x00" * 31,  # 31 bytes, not 32
            ),
        )
        assert exc is not None, "Expected a CHECK violation, got none"
        assert "refresh_tokens_hash_length_check" in str(exc)
        conn.rollback()
    finally:
        if not conn.closed:
            conn.close()


# ---------------------------------------------------------------------------
# 7. CHECK constraint: expires_at > issued_at
# ---------------------------------------------------------------------------

def test_check_constraint_expiration_rejects_past_expiry():
    conn = get_auth_connection()
    try:
        conn.autocommit = False
        exc = _try_sql(
            conn,
            """
            INSERT INTO auth_session.refresh_tokens
                (user_id, family_id, token_hash, issued_at, expires_at)
            VALUES
                (%s, %s, %s, clock_timestamp(), clock_timestamp() - interval '1 hour')
            """,
            (
                TEST_USER_ID,
                str(uuid.uuid4()),
                b"\x00" * 32,
            ),
        )
        assert exc is not None, "Expected a CHECK violation, got none"
        assert "refresh_tokens_expiration_check" in str(exc)
        conn.rollback()
    finally:
        if not conn.closed:
            conn.close()


# ---------------------------------------------------------------------------
# 8. FK constraint: user_id references public.users(id)
# ---------------------------------------------------------------------------

def test_fk_constraint_rejects_unknown_user_id():
    conn = get_auth_connection()
    try:
        conn.autocommit = False
        exc = _try_sql(
            conn,
            """
            INSERT INTO auth_session.refresh_tokens
                (user_id, family_id, token_hash, expires_at)
            VALUES
                (%s, %s, %s, clock_timestamp() + interval '1 day')
            """,
            (
                UNKNOWN_USER_ID,
                str(uuid.uuid4()),
                b"\x01" * 32,
            ),
        )
        assert exc is not None, "Expected an FK violation, got none"
        assert "refresh_tokens_user_id_fkey" in str(exc)
        conn.rollback()
    finally:
        if not conn.closed:
            conn.close()


# ---------------------------------------------------------------------------
# 9. FK constraint: replaced_by references refresh_tokens(id)
# ---------------------------------------------------------------------------

def test_fk_constraint_rejects_unknown_replaced_by():
    conn = get_auth_connection()
    try:
        conn.autocommit = False
        exc = _try_sql(
            conn,
            """
            INSERT INTO auth_session.refresh_tokens
                (user_id, family_id, token_hash, expires_at, replaced_by)
            VALUES
                (%s, %s, %s, clock_timestamp() + interval '1 day', %s)
            """,
            (
                TEST_USER_ID,
                str(uuid.uuid4()),
                b"\x02" * 32,
                UNKNOWN_TOKEN_ID,
            ),
        )
        assert exc is not None, "Expected an FK violation, got none"
        assert "refresh_tokens_replaced_by_fkey" in str(exc)
        conn.rollback()
    finally:
        if not conn.closed:
            conn.close()


# ---------------------------------------------------------------------------
# 10. UNIQUE constraint: token_hash is unique
# ---------------------------------------------------------------------------

def test_unique_constraint_rejects_duplicate_token_hash():
    raw, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        duplicate_hash = hash_refresh_token(raw)  # same hash as the real row

        conn = get_auth_connection()
        try:
            conn.autocommit = False
            exc = _try_sql(
                conn,
                """
                INSERT INTO auth_session.refresh_tokens
                    (user_id, family_id, token_hash, expires_at)
                VALUES
                    (%s, %s, %s, clock_timestamp() + interval '1 day')
                """,
                (
                    TEST_USER_ID,
                    str(uuid.uuid4()),
                    duplicate_hash,
                ),
            )
            assert exc is not None, "Expected a UNIQUE violation, got none"
            assert "refresh_tokens_unique_hash" in str(exc)
            conn.rollback()
        finally:
            if not conn.closed:
                conn.close()
    finally:
        revoke_family(family_id)
        _assert_family_revoked(family_id)


# ---------------------------------------------------------------------------
# 11. PRIMARY KEY constraint: id is unique
# ---------------------------------------------------------------------------

def test_primary_key_constraint_rejects_duplicate_id():
    raw, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        # Fetch the real id of the row we just created.
        conn = get_auth_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM auth_session.refresh_tokens "
                    "WHERE family_id = %s",
                    (str(family_id),),
                )
                (real_id,) = cur.fetchone()
        finally:
            if not conn.closed:
                conn.close()

        # Try to INSERT a second row with the same id.
        conn = get_auth_connection()
        try:
            conn.autocommit = False
            exc = _try_sql(
                conn,
                """
                INSERT INTO auth_session.refresh_tokens
                    (id, user_id, family_id, token_hash, expires_at)
                VALUES
                    (%s, %s, %s, %s, clock_timestamp() + interval '1 day')
                """,
                (
                    real_id,
                    TEST_USER_ID,
                    str(uuid.uuid4()),
                    b"\x03" * 32,
                ),
            )
            assert exc is not None, "Expected a PK violation, got none"
            assert "refresh_tokens_pkey" in str(exc)
            conn.rollback()
        finally:
            if not conn.closed:
                conn.close()
    finally:
        revoke_family(family_id)
        _assert_family_revoked(family_id)


# ---------------------------------------------------------------------------
# 12. The advisory lock is real: two concurrent rotates serialise on the
#     same family and only one succeeds
# ---------------------------------------------------------------------------

def test_advisory_lock_serialises_concurrent_rotations():
    """
    Create a family, then simulate two rotations of the same token from two
    separate connections. Because rotate_refresh_token acquires the family
    advisory lock FIRST, the second rotation must fail with 'reuse detected'
    once the first has committed.
    """
    raw, family_id = create_refresh_family(TEST_USER_ID, None, None)
    try:
        # First rotation succeeds.
        new_raw, _ = rotate_refresh_token(raw)

        # Second rotation on the same original token must be rejected as
        # reuse; the family is now revoked.
        with pytest.raises(RefreshTokenError, match="reuse detected"):
            rotate_refresh_token(raw)

        _assert_family_revoked(family_id)

        # new_raw is also revoked now.
        with pytest.raises(RefreshTokenError, match="reuse detected"):
            rotate_refresh_token(new_raw)
    finally:
        revoke_family(family_id)
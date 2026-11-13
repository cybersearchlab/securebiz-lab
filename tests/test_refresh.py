"""
tests/test_refresh.py
================================================================================
Unit tests for app.services.refresh (no real PostgreSQL, no Vault).

Strategy: mock get_auth_connection. No connection to the real database,
no user creation, no RLS impact.

Coverage:
  A. Generation and hashing (11 functions, 1 parametrized x4 = 14 cases)
  B. Family creation (4 cases)
  C. Rotation (7 cases)
  D. Revocation (6 cases)

Total: 31 cases.

LIMITATIONS (documented, not tested here):
  - PostgreSQL advisory locks are NOT exercised.
  - RLS policies on public.users are NOT exercised.
  - Database constraints (CHECK, FK, UNIQUE) are NOT exercised.
  - The real idempotence of revoke_family (WHERE revoked_at IS NULL) is
    NOT exercised. The corresponding test only verifies that the Python
    service can be called twice without raising on a mock.
================================================================================
"""

import uuid
from unittest.mock import MagicMock, patch

import psycopg
import pytest

from app.services.refresh import (
    RefreshTokenDatabaseError,
    RefreshTokenError,
    create_refresh_family,
    generate_refresh_token,
    hash_refresh_token,
    revoke_family,
    revoke_family_by_raw_token,
    rotate_refresh_token,
)


# A fixed user UUID for tests. Never inserted anywhere.
TEST_USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_connection():
    """Return a MagicMock connection with a cursor context manager."""
    mock_conn = MagicMock()
    mock_conn.closed = False
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    mock_conn.cursor.return_value.__exit__.return_value = False
    return mock_conn, mock_cursor


def _patch_connection(mock_conn):
    """Patch get_auth_connection to return mock_conn."""
    return patch(
        "app.services.refresh.get_auth_connection",
        return_value=mock_conn,
    )


# ---------------------------------------------------------------------------
# A. Generation and hashing (no mock)
# ---------------------------------------------------------------------------

def test_generate_refresh_token_returns_str():
    token = generate_refresh_token()
    assert isinstance(token, str)


def test_generate_refresh_token_is_not_empty():
    assert len(generate_refresh_token()) > 0


def test_generate_refresh_token_length():
    # secrets.token_urlsafe(32) -> 43 chars (256 bits of entropy)
    assert len(generate_refresh_token()) >= 40


def test_generate_refresh_token_is_unique():
    assert generate_refresh_token() != generate_refresh_token()


def test_hash_refresh_token_returns_32_bytes():
    h = hash_refresh_token(generate_refresh_token())
    assert isinstance(h, bytes)
    assert len(h) == 32


def test_hash_refresh_token_is_deterministic():
    token = generate_refresh_token()
    assert hash_refresh_token(token) == hash_refresh_token(token)


def test_hash_refresh_token_different_tokens_differ():
    assert hash_refresh_token(generate_refresh_token()) != hash_refresh_token(generate_refresh_token())


@pytest.mark.parametrize("bad", ["", None, 123, b"bytes"])
def test_hash_refresh_token_rejects_invalid(bad):
    with pytest.raises(RefreshTokenError):
        hash_refresh_token(bad)


def test_refresh_token_error_is_value_error():
    assert issubclass(RefreshTokenError, ValueError)


def test_refresh_token_database_error_is_runtime_error():
    assert issubclass(RefreshTokenDatabaseError, RuntimeError)


def test_refresh_token_database_error_is_not_refresh_token_error():
    assert not issubclass(RefreshTokenDatabaseError, RefreshTokenError)


# ---------------------------------------------------------------------------
# B. Family creation (mock)
# ---------------------------------------------------------------------------

def test_create_refresh_family_inserts_and_commits():
    mock_conn, mock_cur = _make_mock_connection()
    with _patch_connection(mock_conn):
        raw, family_id = create_refresh_family(TEST_USER_ID, None, None)

    assert isinstance(raw, str) and len(raw) > 0
    assert isinstance(family_id, uuid.UUID)
    mock_cur.execute.assert_called_once()
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_create_refresh_family_rolls_back_on_db_error():
    mock_conn, mock_cur = _make_mock_connection()
    mock_cur.execute.side_effect = psycopg.Error("boom")
    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenDatabaseError):
            create_refresh_family(TEST_USER_ID, None, None)

    mock_conn.commit.assert_not_called()
    mock_conn.rollback.assert_called_once()
    mock_conn.close.assert_called_once()


def test_create_refresh_family_passes_user_agent_and_ip():
    # Confirmed from refresh.py: INSERT tuple is
    # (user_id, str(family_id), token_hash, REFRESH_TTL_DAYS, user_agent, ip_address)
    # so params[0] = user_id, params[4] = user_agent, params[5] = ip_address.
    mock_conn, mock_cur = _make_mock_connection()
    with _patch_connection(mock_conn):
        create_refresh_family(TEST_USER_ID, "TestAgent/1.0", "127.0.0.1")

    args, _ = mock_cur.execute.call_args
    params = args[1]
    assert params[0] == TEST_USER_ID
    assert params[4] == "TestAgent/1.0"
    assert params[5] == "127.0.0.1"


def test_create_refresh_family_returns_unique_family_id():
    mock_conn, _ = _make_mock_connection()
    with _patch_connection(mock_conn):
        _, fid1 = create_refresh_family(TEST_USER_ID, None, None)

    mock_conn2, _ = _make_mock_connection()
    with _patch_connection(mock_conn2):
        _, fid2 = create_refresh_family(TEST_USER_ID, None, None)

    assert fid1 != fid2


# ---------------------------------------------------------------------------
# C. Rotation (mock)
# ---------------------------------------------------------------------------

def _rotate_setup(mock_cur, revoked_at=None, is_expired=False,
                  new_id=None, family_id=None, user_id=TEST_USER_ID):
    """Configure fetchone side_effect for rotate_refresh_token."""
    family_id = family_id or uuid.uuid4()
    new_id = new_id or uuid.uuid4()
    old_id = uuid.uuid4()

    mock_cur.fetchone.side_effect = [
        (family_id,),  # Step 1: SELECT family_id
        (old_id, user_id, family_id, revoked_at, is_expired),  # Step 3: FOR UPDATE
        (new_id,),  # INSERT RETURNING id
    ]
    return family_id, old_id, new_id


def test_rotate_refresh_token_returns_new_token_and_user_id():
    mock_conn, mock_cur = _make_mock_connection()
    _rotate_setup(mock_cur)
    with _patch_connection(mock_conn):
        new_raw, user_id = rotate_refresh_token("some-raw-token")

    assert isinstance(new_raw, str) and len(new_raw) > 0
    assert user_id == TEST_USER_ID
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_rotate_refresh_token_rejects_unknown_token():
    mock_conn, mock_cur = _make_mock_connection()
    mock_cur.fetchone.return_value = None  # Step 1: no row
    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenError, match="unknown token"):
            rotate_refresh_token("unknown-raw-token")

    mock_conn.commit.assert_not_called()


def test_rotate_refresh_token_rejects_expired_token():
    mock_conn, mock_cur = _make_mock_connection()
    _rotate_setup(mock_cur, is_expired=True)
    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenError, match="expired"):
            rotate_refresh_token("expired-raw-token")

    mock_conn.commit.assert_not_called()


def test_rotate_refresh_token_detects_reuse_and_commits_before_raise():
    """Verify that family revocation is committed before the error propagates."""
    mock_conn, mock_cur = _make_mock_connection()

    events = []

    def record_commit():
        events.append("commit")

    mock_conn.commit.side_effect = record_commit

    _rotate_setup(
        mock_cur,
        revoked_at="2026-01-01T00:00:00Z",
    )

    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenError, match="reuse detected"):
            rotate_refresh_token("reused-raw-token")

    # The commit side_effect fired exactly once, proving that the family
    # revocation was committed before the exception propagated.
    assert events == ["commit"]
    mock_conn.commit.assert_called_once()
    mock_conn.rollback.assert_not_called()


def test_rotate_refresh_token_rolls_back_on_db_error():
    mock_conn, mock_cur = _make_mock_connection()
    mock_cur.execute.side_effect = psycopg.Error("boom")
    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenDatabaseError):
            rotate_refresh_token("some-raw-token")

    mock_conn.commit.assert_not_called()
    mock_conn.rollback.assert_called_once()


def test_rotate_refresh_token_sets_replaced_by():
    # Confirmed from refresh.py (lines 307-315):
    # UPDATE ... SET revoked_at = ..., replaced_by = %s WHERE id = %s
    # with params (str(new_id), str(old_id)).
    mock_conn, mock_cur = _make_mock_connection()
    family_id, old_id, new_id = _rotate_setup(mock_cur)
    with _patch_connection(mock_conn):
        rotate_refresh_token("some-raw-token")

    last_call = mock_cur.execute.call_args_list[-1]
    params = last_call[0][1]
    assert params == (str(new_id), str(old_id))


def test_rotate_refresh_token_commits_on_success():
    mock_conn, mock_cur = _make_mock_connection()
    _rotate_setup(mock_cur)
    with _patch_connection(mock_conn):
        rotate_refresh_token("some-raw-token")

    mock_conn.commit.assert_called_once()
    mock_conn.rollback.assert_not_called()


# ---------------------------------------------------------------------------
# D. Revocation (mock)
# ---------------------------------------------------------------------------

def test_revoke_family_updates_and_commits():
    mock_conn, mock_cur = _make_mock_connection()
    with _patch_connection(mock_conn):
        revoke_family(uuid.uuid4())

    # Two executes: advisory lock + UPDATE
    assert mock_cur.execute.call_count == 2
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_revoke_family_can_be_called_twice_without_error():
    """Not a real PostgreSQL idempotence test (the mock does not enforce
    the WHERE revoked_at IS NULL). Verifies the service can be invoked twice
    without raising on a mock."""
    mock_conn, _ = _make_mock_connection()
    family_id = uuid.uuid4()
    with _patch_connection(mock_conn):
        revoke_family(family_id)
        revoke_family(family_id)

    assert mock_conn.commit.call_count == 2


def test_revoke_family_rolls_back_on_db_error():
    mock_conn, mock_cur = _make_mock_connection()
    mock_cur.execute.side_effect = psycopg.Error("boom")
    with _patch_connection(mock_conn):
        with pytest.raises(RefreshTokenDatabaseError):
            revoke_family(uuid.uuid4())

    mock_conn.commit.assert_not_called()
    mock_conn.rollback.assert_called_once()


def test_revoke_family_by_raw_token_revokes_family():
    mock_conn, mock_cur = _make_mock_connection()
    family_id = uuid.uuid4()
    mock_cur.fetchone.return_value = (family_id,)
    with _patch_connection(mock_conn):
        revoke_family_by_raw_token("some-raw-token")

    # SELECT family_id, advisory lock, UPDATE
    assert mock_cur.execute.call_count == 3
    mock_conn.commit.assert_called_once()


def test_revoke_family_by_raw_token_noop_on_unknown():
    mock_conn, mock_cur = _make_mock_connection()
    mock_cur.fetchone.return_value = None
    with _patch_connection(mock_conn):
        revoke_family_by_raw_token("unknown-raw-token")

    mock_conn.rollback.assert_called_once()
    mock_conn.commit.assert_not_called()


def test_revoke_family_by_raw_token_noop_on_invalid_input():
    # Empty / non-str input: no DB access at all
    with patch("app.services.refresh.get_auth_connection") as mock_get:
        revoke_family_by_raw_token("")
        revoke_family_by_raw_token(None)
        revoke_family_by_raw_token(123)

    mock_get.assert_not_called()
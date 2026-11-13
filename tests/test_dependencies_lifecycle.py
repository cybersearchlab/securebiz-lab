"""
SecureBiz Lab - Transaction lifecycle tests for get_authenticated_tenant_context.
================================================================================
These tests verify the transactional contract of
app.api.dependencies.get_authenticated_tenant_context():

    sign_context -> get_raw_connection -> install_context
                 -> yield -> cleanup_context -> COMMIT -> CLOSE
  or, on any error after the connection is opened:
    ROLLBACK -> CLOSE   (no cleanup_context)

The function is a FastAPI generator dependency. Each test drives it
manually with next()/throw() and mocks the low-level dependencies:
    - app.api.dependencies.sign_context
    - app.api.dependencies.get_raw_connection

Ordering assertions use a single parent mock with attach_mock() so that
parent.mock_calls records every method call in chronological order. We
then assert the exact subsequence:

    SUCCESS: install_context -> cleanup_context -> commit -> close
    ERROR:   install_context -> rollback -> close   (no cleanup, no commit)

No real PostgreSQL, no Vault, no HTTP. Pure unit tests.

See handover v14.2 section 21.2 (Priority 9 follow-up).
================================================================================
"""

from unittest.mock import MagicMock, call, patch

import psycopg
import pytest
from fastapi import HTTPException

from app.api.dependencies import (
    UserContext,
    get_authenticated_tenant_context,
)


ORG_ID = "1a40e607-b991-4b06-ad1f-13106d65b12a"
ORG_ID_INVALID = "not-a-uuid"
USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
JTI = "11111111-1111-1111-1111-111111111111"

USER = UserContext(user_id=USER_ID, jti=JTI)

PAYLOAD_JSON = '{"aud":"securebiz-postgres","exp":0,"iat":0,"iss":"securebiz-api","jti":"00000000-0000-0000-0000-000000000000","org":"' + ORG_ID + '","sub":"' + USER_ID + '"}'
SIG_BYTES = b"\x00" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_conn(parent):
    """
    Return (conn, cursor) mocks attached to a shared parent, so that
    parent.mock_calls records the full chronological sequence.
    """
    conn = MagicMock(name="conn")
    cursor = MagicMock(name="cursor")
    conn.closed = False
    conn.cursor.return_value.__enter__.return_value = cursor
    conn.cursor.return_value.__exit__.return_value = False
    cursor.fetchone.return_value = (True,)

    parent.attach_mock(cursor, "cursor")
    parent.attach_mock(conn, "conn")
    return conn, cursor


def _has_call_in_order(parent, prefixes):
    """
    Return True iff parent.mock_calls contains, in this order, at least one
    call whose name starts with each prefix in `prefixes`.

    Example:
        _has_call_in_order(p, ["cursor.execute", "conn.commit", "conn.close"])
    is True for:
        [call.cursor.execute(...), call.conn.commit(), call.conn.close()]
    """
    positions = []
    for prefix in prefixes:
        for idx, c in enumerate(parent.mock_calls):
            name = ".".join(str(part) for part in c[:2] if part)
            if name.startswith(prefix):
                positions.append(idx)
                break
        else:
            return False
    return positions == sorted(positions)


def _execute_calls_contain(cursor, needle):
    """Return the list of cursor.execute calls whose first arg contains needle."""
    return [
        c for c in cursor.execute.call_args_list
        if c.args and needle in str(c.args[0])
    ]


# ---------------------------------------------------------------------------
# 1. Success path
# ---------------------------------------------------------------------------

def test_success_path_installs_cleans_up_commits_and_closes():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        yielded = next(gen)
        assert yielded is conn

        with pytest.raises(StopIteration):
            next(gen)

    # install_context and cleanup_context executed exactly once each.
    install_calls = _execute_calls_contain(cursor, "securebiz_install_context")
    cleanup_calls = _execute_calls_contain(cursor, "securebiz_cleanup_context")
    assert len(install_calls) == 1
    assert len(cleanup_calls) == 1

    # commit exactly once, no rollback.
    conn.commit.assert_called_once()
    conn.rollback.assert_not_called()
    conn.close.assert_called_once()

    # Chronological order enforced:
    # install_context -> cleanup_context -> commit -> close
    assert _has_call_in_order(
        parent,
        [
            "cursor.execute",       # install_context
            "cursor.execute",       # cleanup_context
            "conn.commit",
            "conn.close",
        ],
    )


# ---------------------------------------------------------------------------
# 2. Route raises HTTPException
# ---------------------------------------------------------------------------

def test_route_http_exception_rolls_back_and_propagates():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        next(gen)

        with pytest.raises(HTTPException) as exc_info:
            gen.throw(HTTPException(status_code=404, detail="not found"))

        assert exc_info.value.status_code == 404

    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()
    conn.close.assert_called_once()
    cleanup_calls = _execute_calls_contain(cursor, "securebiz_cleanup_context")
    assert cleanup_calls == []

    # Order: install -> rollback -> close (no cleanup, no commit).
    assert _has_call_in_order(
        parent,
        ["cursor.execute", "conn.rollback", "conn.close"],
    )


# ---------------------------------------------------------------------------
# 3. Route raises a non-HTTP exception
# ---------------------------------------------------------------------------

def test_route_unexpected_exception_rolls_back_and_returns_500():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        next(gen)

        with pytest.raises(HTTPException) as exc_info:
            gen.throw(RuntimeError("route boom"))

        assert exc_info.value.status_code == 500

    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()
    conn.close.assert_called_once()
    assert _has_call_in_order(
        parent,
        ["cursor.execute", "conn.rollback", "conn.close"],
    )


# ---------------------------------------------------------------------------
# 4. install_context returns False -> RuntimeError -> 500
# ---------------------------------------------------------------------------

def test_install_context_returns_false_rolls_back_and_returns_500():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)
    cursor.fetchone.return_value = (False,)

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        with pytest.raises(HTTPException) as exc_info:
            next(gen)

        assert exc_info.value.status_code == 500

    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()
    conn.close.assert_called_once()
    assert _has_call_in_order(
        parent,
        ["cursor.execute", "conn.rollback", "conn.close"],
    )


# ---------------------------------------------------------------------------
# 5. cleanup_context raises psycopg.Error (unclassified) -> 500
# ---------------------------------------------------------------------------

def test_cleanup_failure_rolls_back_and_returns_500():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)

    def execute_side_effect(query, *args, **kwargs):
        if "securebiz_cleanup_context" in query:
            raise psycopg.Error("cleanup failed")
        return None

    cursor.execute.side_effect = execute_side_effect

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        next(gen)

        with pytest.raises(HTTPException) as exc_info:
            next(gen)

        assert exc_info.value.status_code == 500

    conn.rollback.assert_called_once()
    conn.commit.assert_not_called()
    conn.close.assert_called_once()
    assert _has_call_in_order(
        parent,
        ["cursor.execute", "conn.rollback", "conn.close"],
    )


# ---------------------------------------------------------------------------
# 6. commit raises -> rollback + 500
# ---------------------------------------------------------------------------

def test_commit_failure_rolls_back_and_returns_500():
    parent = MagicMock(name="parent")
    conn, cursor = _make_mock_conn(parent)
    conn.commit.side_effect = psycopg.Error("commit failed")

    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        return_value=conn,
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        next(gen)

        with pytest.raises(HTTPException) as exc_info:
            next(gen)

        assert exc_info.value.status_code == 500

    conn.commit.assert_called_once()
    conn.rollback.assert_called_once()
    conn.close.assert_called_once()
    # cleanup executed before commit attempt; rollback after commit attempt.
    assert _has_call_in_order(
        parent,
        [
            "cursor.execute",       # install
            "cursor.execute",       # cleanup
            "conn.commit",          # commit attempt (raises)
            "conn.rollback",
            "conn.close",
        ],
    )


# ---------------------------------------------------------------------------
# 7. get_raw_connection raises psycopg.OperationalError -> 503
# ---------------------------------------------------------------------------

def test_connection_failure_returns_503_without_rollback_or_close():
    with patch(
        "app.api.dependencies.sign_context",
        return_value=(PAYLOAD_JSON, SIG_BYTES, "v1", 1),
    ), patch(
        "app.api.dependencies.get_raw_connection",
        side_effect=psycopg.OperationalError("db down"),
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        with pytest.raises(HTTPException) as exc_info:
            next(gen)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Data service unavailable."


# ---------------------------------------------------------------------------
# 8. sign_context raises RuntimeError (Vault) -> 503
# ---------------------------------------------------------------------------

def test_sign_context_runtime_error_returns_503():
    with patch(
        "app.api.dependencies.sign_context",
        side_effect=RuntimeError("vault down"),
    ):
        gen = get_authenticated_tenant_context(
            user=USER, x_organization_id=ORG_ID,
        )
        with pytest.raises(HTTPException) as exc_info:
            next(gen)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail == "Context signing service unavailable."


# ---------------------------------------------------------------------------
# 9. _parse_uuid (invalid header) -> 422
# ---------------------------------------------------------------------------

def test_invalid_uuid_header_returns_422():
    gen = get_authenticated_tenant_context(
        user=USER, x_organization_id=ORG_ID_INVALID,
    )
    with pytest.raises(HTTPException) as exc_info:
        next(gen)

    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# 10. Missing X-Organization-Id -> 400
# ---------------------------------------------------------------------------

def test_missing_org_header_returns_400():
    gen = get_authenticated_tenant_context(
        user=USER, x_organization_id=None,
    )
    with pytest.raises(HTTPException) as exc_info:
        next(gen)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Header X-Organization-Id is required."
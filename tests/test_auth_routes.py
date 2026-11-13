"""
tests/test_auth_routes.py
================================================================================
SecureBiz Lab - Authentication route tests.

Scope:
    POST /auth/login
    POST /auth/refresh
    POST /auth/logout

Strategy:
    - Exercise the real FastAPI routes through HTTPX ASGITransport.
    - Mock PostgreSQL access and refresh-token service functions.
    - Mock JWT creation (Vault is never contacted).
    - Keep the real Argon2id password verifier for login tests.
    - No real PostgreSQL, Vault, user creation or RLS operations.

Limitations:
    - These tests do not validate PostgreSQL SQL execution.
    - They do not validate real Vault/JWT signing.
    - They do not validate refresh-token persistence or concurrency.
    - They do not replace the real database isolation tests.
================================================================================
"""

import asyncio
import importlib
from unittest.mock import MagicMock

import httpx
import psycopg

from app.main import app
from app.services.refresh import (
    RefreshTokenDatabaseError,
    RefreshTokenError,
)


auth_routes = importlib.import_module("app.api.routes.auth")

TEST_EMAIL = "route-tests@example.com"
TEST_PASSWORD = "ValidPassword123!"
TEST_USER_ID = "11111111-1111-4111-8111-111111111111"

# Generate a real Argon2id hash with the application's configured hasher.
TEST_PASSWORD_HASH = auth_routes._hasher.hash(TEST_PASSWORD)


def _request(method, path, payload=None, cookie=None):
    """
    Send one synchronous test request through HTTPX ASGITransport.

    Cookie is explicitly passed as an HTTP header. This avoids depending
    on cookie persistence behavior between separate ASGI client instances.
    """

    async def _send():
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            headers = {}

            if cookie is not None:
                headers["Cookie"] = f"refresh_token={cookie}"

            return await client.request(
                method,
                path,
                json=payload,
                headers=headers,
            )

    return asyncio.run(_send())


def _mock_auth_connection(row):
    """Build a minimal psycopg-compatible connection and cursor mock."""
    conn = MagicMock()
    conn.closed = False

    cursor = MagicMock()
    cursor.fetchone.return_value = row

    conn.cursor.return_value.__enter__.return_value = cursor

    return conn, cursor


def _login_payload(password=TEST_PASSWORD):
    return {
        "email": TEST_EMAIL,
        "password": password,
    }


# ============================================================================
# A. LOGIN - 7 tests
# ============================================================================


def test_login_success_sets_secure_refresh_cookie(monkeypatch):
    """Successful login returns JWT and sets the protected refresh cookie."""
    conn, cursor = _mock_auth_connection(
        (TEST_USER_ID, TEST_PASSWORD_HASH, "active")
    )

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )
    monkeypatch.setattr(
        auth_routes,
        "create_access_token",
        lambda user_id: "fake-access-token",
    )
    monkeypatch.setattr(
        auth_routes,
        "create_refresh_family",
        lambda *args, **kwargs: ("fake-refresh-token", "fake-family-id"),
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 200
    assert response.json()["access_token"] == "fake-access-token"
    assert response.json()["token_type"] == "bearer"
    assert response.json()["expires_in"] > 0

    set_cookie = response.headers.get("set-cookie", "").lower()

    assert "refresh_token=fake-refresh-token" in set_cookie
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/auth" in set_cookie

    cursor.execute.assert_called_once()
    conn.close.assert_called_once()


def test_login_unknown_email_returns_generic_401(monkeypatch):
    """Unknown email returns the same generic authentication error."""
    conn, _ = _mock_auth_connection(None)

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."
    conn.close.assert_called_once()


def test_login_wrong_password_returns_generic_401(monkeypatch):
    """Wrong password must not reveal whether the account exists."""
    conn, _ = _mock_auth_connection(
        (TEST_USER_ID, TEST_PASSWORD_HASH, "active")
    )

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )

    response = _request(
        "POST",
        "/auth/login",
        _login_payload(password="WrongPassword123!"),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."
    conn.close.assert_called_once()


def test_login_inactive_user_returns_generic_401(monkeypatch):
    """An inactive account cannot obtain tokens."""
    conn, _ = _mock_auth_connection(
        (TEST_USER_ID, TEST_PASSWORD_HASH, "disabled")
    )

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."

    conn.close.assert_called_once()


def test_login_database_error_returns_503(monkeypatch):
    """A PostgreSQL error during authentication returns 503."""
    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: (_ for _ in ()).throw(
            psycopg.OperationalError("simulated database failure")
        ),
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


def test_login_jwt_failure_returns_503(monkeypatch):
    """JWT signing failure returns 503 and prevents refresh-family creation."""
    conn, _ = _mock_auth_connection(
        (TEST_USER_ID, TEST_PASSWORD_HASH, "active")
    )

    refresh_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )
    monkeypatch.setattr(
        auth_routes,
        "create_access_token",
        lambda user_id: (_ for _ in ()).throw(
            RuntimeError("simulated signing failure")
        ),
    )
    monkeypatch.setattr(
        auth_routes,
        "create_refresh_family",
        refresh_mock,
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."
    refresh_mock.assert_not_called()


def test_login_refresh_family_failure_returns_503(monkeypatch):
    """A refresh-family database failure returns 503."""
    conn, _ = _mock_auth_connection(
        (TEST_USER_ID, TEST_PASSWORD_HASH, "active")
    )

    monkeypatch.setattr(
        auth_routes,
        "get_auth_connection",
        lambda: conn,
    )
    monkeypatch.setattr(
        auth_routes,
        "create_access_token",
        lambda user_id: "fake-access-token",
    )
    monkeypatch.setattr(
        auth_routes,
        "create_refresh_family",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RefreshTokenDatabaseError("simulated refresh database failure")
        ),
    )

    response = _request("POST", "/auth/login", _login_payload())

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


# ============================================================================
# B. REFRESH - 8 tests
# ============================================================================


def test_refresh_success_rotates_cookie(monkeypatch):
    """Successful refresh returns a new access token and refresh cookie."""
    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: ("new-refresh-token", TEST_USER_ID),
    )
    monkeypatch.setattr(
        auth_routes,
        "_get_user_status",
        lambda user_id: "active",
    )
    monkeypatch.setattr(
        auth_routes,
        "create_access_token",
        lambda user_id: "new-access-token",
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 200
    assert response.json()["access_token"] == "new-access-token"

    set_cookie = response.headers.get("set-cookie", "").lower()

    assert "refresh_token=new-refresh-token" in set_cookie
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/auth" in set_cookie


def test_refresh_missing_cookie_returns_401():
    """Refresh without a cookie is rejected."""
    response = _request("POST", "/auth/refresh")

    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token required."


def test_refresh_invalid_token_returns_401(monkeypatch):
    """An invalid or unknown refresh token returns 401."""
    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: (_ for _ in ()).throw(
            RefreshTokenError("invalid token")
        ),
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="invalid-refresh-token",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token."


def test_refresh_database_error_returns_503(monkeypatch):
    """A database error during token rotation returns 503."""
    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: (_ for _ in ()).throw(
            RefreshTokenDatabaseError("simulated database failure")
        ),
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."


def test_refresh_inactive_user_revokes_new_token(monkeypatch):
    """An inactive user cannot retain the newly rotated refresh token."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: ("new-refresh-token", TEST_USER_ID),
    )
    monkeypatch.setattr(
        auth_routes,
        "_get_user_status",
        lambda user_id: "disabled",
    )
    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token."
    revoke_mock.assert_called_once_with("new-refresh-token")


def test_refresh_unknown_user_revokes_new_token(monkeypatch):
    """A missing user status is treated as invalid and revokes the new token."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: ("new-refresh-token", TEST_USER_ID),
    )
    monkeypatch.setattr(
        auth_routes,
        "_get_user_status",
        lambda user_id: None,
    )
    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token."
    revoke_mock.assert_called_once_with("new-refresh-token")


def test_refresh_status_database_error_revokes_new_token(monkeypatch):
    """A status-check DB failure revokes the rotated token before 503."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: ("new-refresh-token", TEST_USER_ID),
    )
    monkeypatch.setattr(
        auth_routes,
        "_get_user_status",
        lambda user_id: (_ for _ in ()).throw(
            psycopg.OperationalError("simulated status lookup failure")
        ),
    )
    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."
    revoke_mock.assert_called_once_with("new-refresh-token")


def test_refresh_jwt_failure_revokes_new_token(monkeypatch):
    """A JWT signing failure revokes the new refresh token before 503."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "rotate_refresh_token",
        lambda raw_token: ("new-refresh-token", TEST_USER_ID),
    )
    monkeypatch.setattr(
        auth_routes,
        "_get_user_status",
        lambda user_id: "active",
    )
    monkeypatch.setattr(
        auth_routes,
        "create_access_token",
        lambda user_id: (_ for _ in ()).throw(
            RuntimeError("simulated signing failure")
        ),
    )
    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request(
        "POST",
        "/auth/refresh",
        cookie="old-refresh-token",
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."
    revoke_mock.assert_called_once_with("new-refresh-token")


# ============================================================================
# C. LOGOUT - 3 tests
# ============================================================================


def test_logout_revokes_family_and_clears_cookie(monkeypatch):
    """Logout revokes the refresh family and deletes the cookie."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request(
        "POST",
        "/auth/logout",
        cookie="existing-refresh-token",
    )

    assert response.status_code == 200
    assert response.json() == {"status": "logged out"}

    revoke_mock.assert_called_once_with("existing-refresh-token")

    set_cookie = response.headers.get("set-cookie", "").lower()

    assert "refresh_token=" in set_cookie
    assert "path=/auth" in set_cookie
    assert "httponly" in set_cookie
    assert "secure" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "max-age=0" in set_cookie


def test_logout_without_cookie_is_noop(monkeypatch):
    """Logout without a refresh cookie succeeds without DB/service access."""
    revoke_mock = MagicMock()

    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        revoke_mock,
    )

    response = _request("POST", "/auth/logout")

    assert response.status_code == 200
    assert response.json() == {"status": "logged out"}
    revoke_mock.assert_not_called()


def test_logout_database_error_returns_503(monkeypatch):
    """A real refresh-family database failure must not be hidden by logout."""
    monkeypatch.setattr(
        auth_routes,
        "revoke_family_by_raw_token",
        lambda raw_token: (_ for _ in ()).throw(
            RefreshTokenDatabaseError("simulated database failure")
        ),
    )

    response = _request(
        "POST",
        "/auth/logout",
        cookie="existing-refresh-token",
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Authentication service unavailable."
"""
app/api/routes/auth.py
================================================================================
SecureBiz Lab - Authentication routes
================================================================================

Endpoints:
    POST /auth/login    - verify credentials, issue access JWT + refresh cookie.
    POST /auth/refresh  - rotate refresh token, issue new access JWT.
    POST /auth/logout   - revoke the refresh family, clear the cookie.

This file MUST NOT contain:
    - JWT signing secret (see app.core.vault).
    - Refresh token storage or rotation logic (see app.services.refresh).
    - Password hashing implementation (delegated to auth_private.authenticate
      and argon2.PasswordHasher, which are called from here).
    - Tenant context installation (see app.api.dependencies).

Security notes:
    - The refresh cookie is HttpOnly, Secure, SameSite=Strict, Path=/auth,
      Max-Age=REFRESH_TTL_DAYS * 86400. It is never exposed to JavaScript.
    - Access tokens are short-lived (JWT_ACCESS_TTL_SECONDS, 15 min default).
    - Login failures return a generic 401 "Invalid credentials." regardless
      of whether the email exists. A dummy Argon2 verification is performed
      when the email is unknown, to equalize timing and prevent enumeration.
    - On refresh, the user status is re-checked (auth_session.get_user_status).
      If the account is no longer 'active', the family is revoked and the
      request is rejected. If the status check itself fails (DB unavailable),
      the newly rotated token is revoked before returning 503, so it does
      not linger active without ever being handed to the client.
    - On logout, the family is revoked before clearing the cookie. A real
      DB failure during revocation returns 503, not 200: idempotence must
      not mask an infrastructure failure. Missing/unknown token is a 200
      no-op.
    - Exception contract (see app.services.refresh):
        * RefreshTokenError (ValueError) -> HTTP 401 (invalid token).
        * RefreshTokenDatabaseError (RuntimeError) -> HTTP 503 (DB down).
      The two do not inherit from each other, so a 401 handler cannot swallow
      a database failure by accident.

Password format:
    _verify_password() uses argon2.PasswordHasher with the parameters locked
    in the v12 handover (time_cost=2, memory_cost=19456, parallelism=1,
    hash_len=32, salt_len=16). Only Argon2id hashes are accepted. Any other
    format (bcrypt, PBKDF2, plaintext) causes verify() to raise
    InvalidHashError, which is caught and returns False -> HTTP 401. There is
    no fallback.

    Account provisioning (creating users with Argon2id hashes) is out of scope
    for Priority 5. auth_private.credentials is currently empty (verified
    2026-11-12: 0 rows, 0 Argon2id, 0 bcrypt).
================================================================================
"""

# 1. Standard library
import logging

# 2. Third-party
import psycopg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Cookie, HTTPException, Response, status

# 3. Local
from app.core.config import settings
from app.core.database import get_auth_connection
from app.core.jwt import create_access_token
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.refresh import (
    RefreshTokenDatabaseError,
    RefreshTokenError,
    create_refresh_family,
    revoke_family_by_raw_token,
    rotate_refresh_token,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

# Argon2id verifier. Parameters must match the ones used at hash time:
# time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16.
# Only verification is performed here; hashing is done offline during user
# provisioning.
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

# Pre-computed dummy hash, used to equalize login timing when the email is
# unknown. The plaintext is irrelevant: we only call verify() and discard the
# result. This hash is NOT tied to any user account and never authenticates.
_DUMMY_PASSWORD_HASH = _hasher.hash("dummy-password-for-timing-equalization")


# Refresh cookie configuration.
_REFRESH_COOKIE_NAME = "refresh_token"
_REFRESH_COOKIE_PATH = "/auth"
_REFRESH_COOKIE_MAX_AGE = settings.REFRESH_TTL_DAYS * 86400


def _set_refresh_cookie(response: Response, raw_token: str) -> None:
    """Set the refresh token cookie with the project-wide security attributes."""
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=raw_token,
        max_age=_REFRESH_COOKIE_MAX_AGE,
        path=_REFRESH_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Delete the refresh cookie, with the same security attributes as creation."""
    response.delete_cookie(
        key=_REFRESH_COOKIE_NAME,
        path=_REFRESH_COOKIE_PATH,
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _verify_password(password_hash: str | None, plain_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.

    A None or malformed hash returns False (no 500 leak).
    """
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _get_user_status(user_id: str) -> str | None:
    """
    Read public.users.status via auth_session.get_user_status(uuid).

    Returns None if the user is unknown. May raise psycopg.Error on DB
    unavailability; the caller decides how to react.
    """
    conn = get_auth_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT auth_session.get_user_status(%s::uuid)",
                (user_id,),
            )
            row = cur.fetchone()
    finally:
        if not conn.closed:
            conn.close()
    if row is None:
        return None
    return row[0]


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest, response: Response):
    """
    Verify email + password, issue an access JWT and a refresh cookie.

    Returns 401 on any failure (unknown email, wrong password, inactive user)
    with a generic message to prevent account enumeration. Returns 503 on
    database or service unavailability.
    """
    generic_401 = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials.",
    )

    # Step 1: fetch (user_id, password_hash, status) via SECURITY DEFINER.
    auth_conn = None
    try:
        auth_conn = get_auth_connection()
        with auth_conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, password_hash, status "
                "FROM auth_private.authenticate(%s)",
                (str(request.email),),
            )
            row = cur.fetchone()
    except psycopg.Error:
        logger.error("login: authenticate() failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None
    finally:
        if auth_conn is not None and not auth_conn.closed:
            auth_conn.close()

    # Step 2: unknown email -> dummy Argon2 verify, then generic 401.
    if row is None:
        _verify_password(_DUMMY_PASSWORD_HASH, request.password)
        raise generic_401

    user_id, password_hash, db_status = row

    # Step 3: verify password.
    if not _verify_password(password_hash, request.password):
        raise generic_401

    # Step 4: reject inactive accounts.
    if db_status != "active":
        raise generic_401

    # Step 5: issue access JWT.
    try:
        access_token = create_access_token(str(user_id))
    except RuntimeError:
        logger.error("login: create_access_token failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None

    # Step 6: create refresh family and set cookie.
    try:
        raw_refresh, _family_id = create_refresh_family(
            str(user_id), user_agent=None, ip_address=None
        )
    except RefreshTokenDatabaseError:
        logger.error("login: create_refresh_family failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None

    _set_refresh_cookie(response, raw_refresh)

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.JWT_ACCESS_TTL_SECONDS,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
):
    """
    Rotate the refresh token and issue a new access JWT.

    Returns:
        401 - missing cookie, invalid token, inactive user.
        503 - database or signing failure. If rotation already committed,
              the new token is revoked so it does not remain active without
              being handed to the client.
    """
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required.",
        )

    # Step 1: rotate.
    try:
        new_raw, user_id = rotate_refresh_token(refresh_token)
    except RefreshTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        ) from None
    except RefreshTokenDatabaseError:
        logger.error("refresh: rotate_refresh_token failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None

    # Step 2: re-check status. DB failure here must not leave new_raw active
    # without ever being delivered to the client.
    try:
        db_status = _get_user_status(user_id)
    except psycopg.Error:
        logger.error("refresh: get_user_status failed")
        try:
            revoke_family_by_raw_token(new_raw)
        except (RefreshTokenError, RefreshTokenDatabaseError):
            logger.error("refresh: failed to revoke new_raw after status check failure")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None

    if db_status != "active":
        try:
            revoke_family_by_raw_token(new_raw)
        except (RefreshTokenError, RefreshTokenDatabaseError):
            logger.error("refresh: failed to revoke family for inactive user")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        ) from None

    # Step 3: issue JWT. If signing fails, revoke new_raw.
    try:
        access_token = create_access_token(user_id)
    except RuntimeError:
        logger.error("refresh: create_access_token failed")
        try:
            revoke_family_by_raw_token(new_raw)
        except (RefreshTokenError, RefreshTokenDatabaseError):
            logger.error("refresh: failed to revoke new_raw after JWT issuance failure")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None

    _set_refresh_cookie(response, new_raw)

    return TokenResponse(
        access_token=access_token,
        expires_in=settings.JWT_ACCESS_TTL_SECONDS,
    )


@router.post("/logout")
def logout(
    response: Response,
    refresh_token: str | None = Cookie(default=None, alias=_REFRESH_COOKIE_NAME),
):
    """
    Revoke the refresh family (if a token is present) and clear the cookie.

    Returns:
        200 - cookie absent, token unknown (no-op), or successful revocation.
        503 - real DB failure during revocation.
    """
    if refresh_token:
        try:
            revoke_family_by_raw_token(refresh_token)
        except RefreshTokenDatabaseError:
            logger.error("logout: failed to revoke family")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable.",
            ) from None

    _clear_refresh_cookie(response)
    return {"status": "logged out"}

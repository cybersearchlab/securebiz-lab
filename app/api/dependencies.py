"""
app/api/dependencies.py
================================================================================
SecureBiz Lab - FastAPI dependencies.

Responsibilities:
    - Provide get_tenant_context() to routes.
    - Enforce the single-transaction invariant:
        install_context -> business queries -> cleanup_context -> COMMIT
      or, on any error:
        install_context -> rollback (context destroyed with transaction) -> CLOSE
    - Fail-fast if the environment is misconfigured (debug headers in prod).

This file MUST NOT contain:
    - SQL business queries (belongs to routes).
    - Context signing logic (belongs to app/services/context_signing.py).
    - JWT validation (belongs to Phase 4).

Constraints (validated 2026-11-10):
    - install_context() and cleanup_context() MUST share the same transaction.
    - On success: cleanup_context() then commit().
    - On any exception: rollback() (which also destroys the context) then close().
    - Never call cleanup_context() after a rollback (context is already gone).
    - DEBUG_HEADERS defaults to false (secure by default).
================================================================================
"""

import logging
import os
import uuid
from typing import Generator

from fastapi import Header, HTTPException, status
import psycopg
from psycopg import Connection

from app.core.database import get_raw_connection
from app.services.context_signing import sign_context

logger = logging.getLogger(__name__)

# SQL business refusals -> HTTP 403.
_REFUSAL_MESSAGES_403 = frozenset({
    "Inactive or unauthorized user membership",
})

# Transient context / signing-key failures -> HTTP 503.
_TRANSIENT_MESSAGES_503 = frozenset({
    "Token expired",
    "Unknown or revoked signing key",
})

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEBUG_HEADERS_ENABLED = (
    os.getenv("DEBUG_HEADERS", "false").strip().lower() == "true"
)


def _parse_uuid(value: str, header_name: str) -> str:
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Header {header_name} must be a valid UUID.",
        )


def get_tenant_context(
    x_debug_user_id: str | None = Header(default=None, alias="X-Debug-User-Id"),
    x_debug_org_id: str | None = Header(default=None, alias="X-Debug-Org-Id"),
) -> Generator[Connection, None, None]:
    """
    FastAPI dependency: install a signed tenant context for the request.

    Yields a psycopg connection whose transaction carries the installed
    context. The caller MUST NOT call commit() or rollback() on this
    connection; this dependency owns the full lifecycle.
    """
    # --- 1. Environment guards ---
    if APP_ENV == "production":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Debug headers are not allowed in production.",
        )

    if not DEBUG_HEADERS_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required (JWT not yet implemented — Phase 4).",
        )

    if not x_debug_user_id or not x_debug_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Headers X-Debug-User-Id and X-Debug-Org-Id are required in Phase A.",
        )

    user_id = _parse_uuid(x_debug_user_id, "X-Debug-User-Id")
    org_id = _parse_uuid(x_debug_org_id, "X-Debug-Org-Id")

    logger.warning(
        "DEBUG IMPERSONATION: user=%s org=%s (APP_ENV=%s)",
        user_id, org_id, APP_ENV,
    )

    # --- 2. Sign context (before touching the DB) ---
    try:
        payload_json, sig_bytes, vault_version, key_version = sign_context(
            user_id, org_id
        )
    except Exception as exc:
        logger.error("Context signing failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Context signing failed.",
        )

    # --- 3. Open connection, install, yield, cleanup, commit/rollback ---
    conn = get_raw_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT auth_security.securebiz_install_context(%s, %s, %s)",
                (payload_json, sig_bytes, "securebiz-context"),
            )
            row = cur.fetchone()
            if not row or row[0] is not True:
                raise RuntimeError("install_context did not return True")

        logger.debug(
            "Context installed: user=%s org=%s vault_version=%s key_version=%s",
            user_id, org_id, vault_version, key_version,
        )

        # --- 4. Yield: all route queries share this transaction ---
        yield conn

        # --- 5. Success path: cleanup, then commit ---
        with conn.cursor() as cur:
            cur.execute("SELECT auth_security.securebiz_cleanup_context()")
        conn.commit()

    except HTTPException:
        # Route raised an HTTP error (404, 403...): rollback and propagate.
        conn.rollback()
        raise

    except Exception as exc:
        # install_context, business query, or cleanup failed:
        # rollback destroys the context along with the transaction.
        conn.rollback()
        logger.error("Tenant context request failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Request failed.",
        )

    finally:
        if not conn.closed:
            conn.close()




# ============================================================================
# Authenticated dependencies (Priority 5)
# ============================================================================
#
# These dependencies are the JWT-authenticated counterpart of
# get_tenant_context(). They are NOT a replacement for it: the historical
# function is kept untouched so that tests/test_isolation.py continues to
# exercise the debug-header path until Priority 9 migrates them.
#
# Contract:
#   - get_current_user() validates a Bearer JWT and returns UserContext.
#   - get_authenticated_tenant_context() installs a signed tenant context
#     using the user_id from the JWT and the organization id from the
#     X-Organization-Id header, then yields a connection with the same
#     transaction lifecycle as get_tenant_context().
#
# Exception mapping (in get_current_user):
#   - Missing / malformed Authorization header  -> 401
#   - TokenValidationError from jwt.py          -> 401
#   - RuntimeError (Vault secret unavailable)   -> 503
#   - Any other Exception                       -> 500 (internal error)
#     500 is generic and does not leak details. It is NOT mapped to 503:
#     a programming bug is not a service unavailability.
#
# Logging:
#   - Successful authentications are NOT logged (no jti, no user_id).
#   - Rejections log the class of failure only, never the raw exception
#     message (which may contain sensitive data from external components).
# ============================================================================


from dataclasses import dataclass  # noqa: E402

from fastapi import Depends  # noqa: E402

from app.core.jwt import TokenValidationError, verify_access_token  # noqa: E402


@dataclass(frozen=True)
class UserContext:
    """Authenticated user identity extracted from a verified JWT."""

    user_id: str
    jti: str


def get_current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> UserContext:
    """
    FastAPI dependency: validate the Bearer access token and return the user.

    Returns:
        401 - missing or malformed Authorization header, invalid or expired
              token, or any TokenValidationError raised by verify_access_token.
        503 - Vault unavailable (RuntimeError from get_jwt_secret).
        500 - any other unexpected error. Generic message, no details.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    token = authorization[len("Bearer "):].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    try:
        claims = verify_access_token(token)
    except TokenValidationError:
        logger.warning("get_current_user: token rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        ) from None
    except RuntimeError:
        # get_jwt_secret() raises RuntimeError when Vault is unreachable.
        logger.error("get_current_user: JWT secret unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service unavailable.",
        ) from None
    except Exception:
        # Programming error, not an infrastructure failure. Do not mask as 503.
        logger.error("get_current_user: unexpected internal error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error.",
        ) from None

    return UserContext(user_id=claims["sub"], jti=claims["jti"])


def get_authenticated_tenant_context(
    user: UserContext = Depends(get_current_user),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> Generator[Connection, None, None]:
    """
    FastAPI dependency: install a signed tenant context for an authenticated
    user.

    Same transaction lifecycle as get_tenant_context():
        sign_context -> open_connection -> install_context
                     -> yield -> cleanup_context -> COMMIT
      or, on any error after the connection is opened:
        ROLLBACK -> CLOSE   (no cleanup_context: the transaction is gone)

    The user identity comes from the verified JWT (get_current_user), not
    from debug headers. The organization id comes from X-Organization-Id.
    Membership verification remains the responsibility of
    auth_security.securebiz_install_context() in PostgreSQL.
    """
    if not x_organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header X-Organization-Id is required.",
        )

    org_id = _parse_uuid(x_organization_id, "X-Organization-Id")
    user_id = user.user_id

    # Step 1: sign context (before touching the DB).
    try:
        payload_json, sig_bytes, vault_version, key_version = sign_context(
            user_id, org_id
        )
    except ValueError:
        # Invalid input: _parse_uuid should already have rejected it.
        logger.error("Authenticated context signing failed: invalid input")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error.",
        ) from None
    except RuntimeError:
        # Vault unavailable or Transit signing failure.
        logger.error("Authenticated context signing failed: Vault unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Context signing service unavailable.",
        ) from None
    except Exception:
        # Unexpected signing failure.
        logger.error("Authenticated context signing failed: unexpected")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error.",
        ) from None

    # Step 2: open the connection inside the try, so that psycopg.Error
    # during connection open is handled as a data-service unavailability.
    conn: Connection | None = None
    try:
        conn = get_raw_connection()

        # Step 3: install the signed context.
        with conn.cursor() as cur:
            cur.execute(
                "SELECT auth_security.securebiz_install_context(%s, %s, %s)",
                (payload_json, sig_bytes, "securebiz-context"),
            )
            row = cur.fetchone()
            if not row or row[0] is not True:
                raise RuntimeError("install_context did not return True")

        logger.debug(
            "Authenticated context installed: vault_version=%s key_version=%s",
            vault_version, key_version,
        )

        # Step 4: yield the connection to the route.
        yield conn

        # Step 5: success path — cleanup, then commit.
        with conn.cursor() as cur:
            cur.execute("SELECT auth_security.securebiz_cleanup_context()")
        conn.commit()

    except HTTPException:
        # Route raised an HTTP error (4xx, 5xx): rollback and propagate.
        if conn is not None and not conn.closed:
            conn.rollback()
        raise

    except psycopg.OperationalError:
        # Database connection or operational failure.
        if conn is not None and not conn.closed:
            conn.rollback()
        logger.error("Authenticated tenant context: database unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Data service unavailable.",
        ) from None

    except psycopg.Error as exc:
        # Classify PostgreSQL business / security exceptions.
        if conn is not None and not conn.closed:
            conn.rollback()

        msg = exc.diag.message_primary if exc.diag else None

        if msg in _REFUSAL_MESSAGES_403:
            logger.warning("Authenticated tenant context: access refused")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied.",
            ) from None

        if msg in _TRANSIENT_MESSAGES_503:
            logger.warning("Authenticated tenant context: transient failure")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Context service unavailable.",
            ) from None

        # Replay, invalid signature and all unclassified SQL errors
        # remain generic internal errors.
        logger.error("Authenticated tenant context: unexpected SQL error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error.",
        ) from None

    except Exception:
        # Programming error or unexpected failure: rollback, return generic 500.
        if conn is not None and not conn.closed:
            conn.rollback()
        logger.error("Authenticated tenant context: unexpected internal error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error.",
        ) from None

    finally:
        if conn is not None and not conn.closed:
            conn.close()

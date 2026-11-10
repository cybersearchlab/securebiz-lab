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
from psycopg import Connection

from app.core.database import get_raw_connection
from app.services.context_signing import sign_context

logger = logging.getLogger(__name__)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEBUG_HEADERS_ENABLED = (
    os.getenv("DEBUG_HEADERS", "false").strip().lower() == "true"
)


def _parse_uuid(value: str, header_name: str) -> str:
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
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



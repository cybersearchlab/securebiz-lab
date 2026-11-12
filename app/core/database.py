"""
app/core/database.py
================================================================================
SecureBiz Lab - PostgreSQL Connection Management
================================================================================

Responsibilities:
    - Create psycopg3 connections to the PostgreSQL database.
    - Provide a context manager for safe connection handling.
    - Provide a raw connection factory for callers that manage their
      own transaction lifecycle (e.g. FastAPI tenant context).
    - Provide a dedicated authentication connection using securebiz_auth.

This file MUST NOT contain:
    - SQL queries (belongs to models, services, or migrations).
    - Context signing logic (belongs to security.py).
    - Business logic.

================================================================================
"""

# 1. Standard library
from contextlib import contextmanager
from typing import Generator

# 2. Third-party
import psycopg
from psycopg import Connection

# 3. Local
from app.core.config import settings


def _connect(user: str, password: str) -> Connection:
    """
    Internal helper: open a psycopg3 connection with explicit credentials.

    The caller is responsible for commit, rollback and close.
    """
    return psycopg.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        dbname=settings.DB_NAME,
        user=user,
        password=password,
        connect_timeout=3,
    )


def get_raw_connection() -> Connection:
    """
    Open a PostgreSQL connection with the business role (securebiz_app).

    The caller is responsible for commit, rollback and close.
    """
    return _connect(settings.DB_USER, settings.DB_PASSWORD)


def get_auth_connection() -> Connection:
    """
    Open a PostgreSQL connection with the authentication role (securebiz_auth).

    Used exclusively by the login flow to call auth_private.authenticate()
    and by the refresh flow to manage auth_session.refresh_tokens.

    The caller is responsible for commit, rollback and close.
    """
    return _connect(settings.AUTH_DB_USER, settings.AUTH_DB_PASSWORD)


def get_database_connection() -> Connection:
    """
    Backward-compatible alias for get_raw_connection().
    """
    return get_raw_connection()


@contextmanager
def get_database_session() -> Generator[Connection, None, None]:
    """
    Provide a transactional database session.

    Uses the business role (securebiz_app).
    """
    connection = get_raw_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

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

This file MUST NOT contain:
    - SQL queries (belongs to models, services, or migrations).
    - Context signing logic (belongs to security.py).
    - Business logic.

Design Note:
    Psycopg3's connect() returns a connection object that acts as a
    context manager. When the `with` block exits, the transaction is
    committed automatically (if no exception occurred).
    If an exception occurs, it is rolled back automatically.

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


def get_raw_connection() -> Connection:
    """
    Open a PostgreSQL connection without managing its transaction.

    The caller is responsible for commit, rollback and close.

    Returns:
        Connection: An open psycopg3 connection object.

    Raises:
        psycopg.OperationalError: If the database is unreachable or credentials
            are invalid.
    """
    return psycopg.connect(
        host=settings.DB_HOST,
        port=settings.DB_PORT,
        dbname=settings.DB_NAME,
        user=settings.DB_USER,
        password=settings.DB_PASSWORD,
        connect_timeout=3,
    )


def get_database_connection() -> Connection:
    """
    Create a new PostgreSQL connection using the validated application settings.

    Kept for backward compatibility. Delegates to get_raw_connection().
    """
    return get_raw_connection()


@contextmanager
def get_database_session() -> Generator[Connection, None, None]:
    """
    Provide a transactional database session.

    This context manager opens a connection, yields it for use within
    the block, and guarantees that the transaction is either committed
    (on success) or rolled back (on exception).

    Yields:
        Connection: The active PostgreSQL connection.
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

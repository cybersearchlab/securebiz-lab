
"""
app/services/refresh.py
================================================================================
SecureBiz Lab - Opaque Refresh Token Management
================================================================================

Responsibilities:
    - Generate opaque, 256-bit refresh tokens.
    - Hash them (SHA-256) for storage in auth_session.refresh_tokens.
    - Create a refresh family at login.
    - Rotate refresh tokens on every use, with reuse detection.
    - Revoke an entire family (logout, password change, reuse).
    - Revoke a family starting from a raw token (logout endpoint).

This file MUST NOT contain:
    - The JWT signing secret (see app.core.vault).
    - Access token issuance/verification (see app.core.jwt).
    - API routes or business logic (see app.api.routes.auth).
    - Password hashing (see the login flow).

Design Notes:
    - Refresh tokens are opaque: not JWTs, not self-contained. The server is
      the sole authority on their validity.
    - Only the SHA-256 hash is stored. The raw token is returned to the caller
      once and never persisted.
    - Rotation is transactional. The flow is:
        1. SELECT family_id by token_hash (no lock).
        2. pg_advisory_xact_lock on family_id.
        3. SELECT ... FOR UPDATE on token_hash (re-read under lock).
        4. Validate revoked_at FIRST (reuse detection takes precedence over
           expiry, so that a replayed, expired, revoked token still revokes
           its family), then is_expired.
        5. INSERT replacement, UPDATE old row.
        6. COMMIT.
    - Family-level serialization uses pg_advisory_xact_lock(hashtextextended(
      family_id::text, 0)). All three functions (rotate, revoke, revoke_by_raw)
      acquire the family lock BEFORE any row lock. This avoids the deadlock
      that would arise from the opposite order:
        A: FOR UPDATE row  -> waits for family lock held by B
        B: family lock     -> waits for FOR UPDATE row held by A
      which PostgreSQL would detect and resolve by aborting one transaction.
    - The advisory lock is transactional (auto-released on COMMIT/ROLLBACK)
      and uses a 64-bit hash. A collision would over-serialize two unrelated
      families, not break isolation.
    - No-deadlock guarantee applies to operations that follow this protocol.
      A direct SQL UPDATE on refresh_tokens that does not take the family
      lock would break it. Do not add such statements.
    - The auth_session.refresh_tokens table has:
        CHECK octet_length(token_hash) = 32
        CHECK expires_at > issued_at
        FK replaced_by -> refresh_tokens(id)
        FK user_id     -> users(id) ON DELETE CASCADE
      These constraints are honored by construction.
    - make_interval(days => %s) is used instead of string concatenation to
      avoid any ambiguity if REFRESH_TTL_DAYS changes type in the future.

================================================================================
"""

# 1. Standard library
import hashlib
import secrets
import uuid

# 2. Third-party
import psycopg
from psycopg import Connection

# 3. Local
from app.core.config import settings
from app.core.database import get_auth_connection


# 256 bits of entropy before encoding. token_urlsafe returns a str.
REFRESH_TOKEN_BYTES = 32


class RefreshTokenError(ValueError):
    """Raised when a refresh token is invalid, expired, revoked, or reused."""


class RefreshTokenDatabaseError(RuntimeError):
    """
    Raised when a database access or execution error occurs during a refresh
    token operation.

    This is an infrastructure failure, not a business validation failure.
    Callers must map it to HTTP 503, not 401. It deliberately does NOT inherit
    from RefreshTokenError so that ``except RefreshTokenError`` cannot catch it
    by accident.
    """


def generate_refresh_token() -> str:
    """Return a fresh opaque refresh token (256 bits of entropy)."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> bytes:
    """
    Return the SHA-256 hash of the given refresh token.

    Exactly 32 bytes, matching the CHECK constraint on token_hash.
    """
    if not isinstance(token, str) or not token:
        raise RefreshTokenError("token must be a non-empty string") from None
    return hashlib.sha256(token.encode("utf-8")).digest()


def _close_quietly(conn: Connection | None) -> None:
    """Close a connection without raising."""
    if conn is not None and not conn.closed:
        try:
            conn.close()
        except Exception:
            pass


def _acquire_family_lock(cur, family_id) -> None:
    """
    Acquire a transactional advisory lock on the given family.

    MUST be called before any row-level lock on refresh_tokens, to keep the
    lock order (family -> row) consistent across all three functions. The
    opposite order would deadlock (see module docstring).
    """
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (str(family_id),),
    )


def create_refresh_family(
    user_id: str,
    user_agent: str | None,
    ip_address: str | None,
) -> tuple[str, uuid.UUID]:
    """
    Create a new refresh-token family and insert its first token.

    Args:
        user_id: canonical UUID string of the user.
        user_agent: optional User-Agent header value.
        ip_address: optional client IP (string form of an IPv4 or IPv6 address).

    Returns:
        (raw_token, family_id)

    Raises:
        RefreshTokenDatabaseError: if a database operation fails.
    """
    raw = generate_refresh_token()
    token_hash = hash_refresh_token(raw)
    family_id = uuid.uuid4()

    conn: Connection | None = None
    try:
        conn = get_auth_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO auth_session.refresh_tokens
                    (user_id, family_id, token_hash, expires_at, user_agent, ip_address)
                VALUES
                    (%s, %s, %s, clock_timestamp() + make_interval(days => %s), %s, %s::inet)
                """,
                (
                    user_id,
                    str(family_id),
                    token_hash,
                    settings.REFRESH_TTL_DAYS,
                    user_agent,
                    ip_address,
                ),
            )
        conn.commit()
        return raw, family_id
    except psycopg.Error:
        if conn is not None and not conn.closed:
            try:
                conn.rollback()
            except Exception:
                pass
        raise RefreshTokenDatabaseError("failed to create refresh family") from None
    finally:
        _close_quietly(conn)


def rotate_refresh_token(raw_token: str) -> tuple[str, str]:
    """
    Validate a refresh token, revoke it, and issue a replacement in the same
    family. Detects reuse and revokes the entire family if reuse is detected.

    Transaction semantics (lock order: family -> row):
        1. SELECT family_id by token_hash, no lock. The family_id is
           immutable per token, so reading it before locking is safe.
        2. pg_advisory_xact_lock on family_id. Serializes this rotation with
           any concurrent rotate/revoke on the same family.
        3. SELECT ... FOR UPDATE on token_hash. Re-reads the row under the
           family lock. From here on, no other transaction can modify the
           family (all mutators hold the family lock first).
        4. Validate revoked_at BEFORE is_expired. A replayed token that is
           both expired and revoked must still trigger reuse detection and
           family revocation. Only then check expiry.
        5. INSERT replacement, UPDATE old row.
        6. COMMIT.

    Returns:
        (new_raw_token, user_id)

    Raises:
        RefreshTokenError: if the token is invalid, expired, or reused.
        RefreshTokenDatabaseError: if a database operation fails.
    """
    token_hash = hash_refresh_token(raw_token)

    conn: Connection | None = None
    try:
        conn = get_auth_connection()

        with conn.cursor() as cur:
            # Step 1: read family_id without locking the token row.
            cur.execute(
                "SELECT family_id FROM auth_session.refresh_tokens WHERE token_hash = %s",
                (token_hash,),
            )
            row = cur.fetchone()
            if row is None:
                raise RefreshTokenError("unknown token") from None
            family_id = row[0]

            # Step 2: acquire the family lock FIRST. Consistent lock order
            # across rotate / revoke / revoke_by_raw prevents deadlock.
            _acquire_family_lock(cur, family_id)

            # Step 3: re-read the row under the family lock, with FOR UPDATE.
            cur.execute(
                """
                SELECT id, user_id, family_id, revoked_at,
                       (expires_at <= clock_timestamp()) AS is_expired
                  FROM auth_session.refresh_tokens
                 WHERE token_hash = %s
                 FOR UPDATE
                """,
                (token_hash,),
            )
            row = cur.fetchone()

            if row is None:
                # The row disappeared between Step 1 and Step 3. This can
                # only happen if another transaction deleted it while we
                # were acquiring the family lock — which our locking protocol
                # forbids (all mutators hold the family lock first). Treat it
                # as an invalid state.
                raise RefreshTokenError("invalid token state") from None

            old_id, user_id, locked_family_id, revoked_at, is_expired = row

            if locked_family_id != family_id:
                # Defensive assertion. family_id is immutable per token.
                raise RefreshTokenError("invalid token state") from None

            # Step 4a: reuse detection takes precedence over expiry. A token
            # that is both expired and revoked has been replayed; it must
            # revoke its family, not just be rejected as expired.
            if revoked_at is not None:
                # Reuse detected: revoke the entire family and COMMIT before
                # raising so the revocation survives the caller's rollback.
                cur.execute(
                    """
                    UPDATE auth_session.refresh_tokens
                       SET revoked_at = clock_timestamp()
                     WHERE family_id = %s
                       AND revoked_at IS NULL
                    """,
                    (str(family_id),),
                )
                conn.commit()
                raise RefreshTokenError("reuse detected") from None

            # Step 4b: expiry check, only after reuse has been ruled out.
            if is_expired:
                raise RefreshTokenError("expired") from None

            # Normal rotation.
            new_raw = generate_refresh_token()
            new_hash = hash_refresh_token(new_raw)

            cur.execute(
                """
                INSERT INTO auth_session.refresh_tokens
                    (user_id, family_id, token_hash, expires_at)
                VALUES
                    (%s, %s, %s, clock_timestamp() + make_interval(days => %s))
                RETURNING id
                """,
                (
                    str(user_id),
                    str(family_id),
                    new_hash,
                    settings.REFRESH_TTL_DAYS,
                ),
            )
            new_id = cur.fetchone()[0]

            cur.execute(
                """
                UPDATE auth_session.refresh_tokens
                   SET revoked_at = clock_timestamp(),
                       replaced_by = %s
                 WHERE id = %s
                """,
                (str(new_id), str(old_id)),
            )

        conn.commit()
        return new_raw, str(user_id)

    except RefreshTokenError:
        # Reuse detection already committed above; other RefreshTokenError
        # cases (unknown, expired, invalid state) leave the implicit
        # transaction to be rolled back by close().
        raise
    except psycopg.Error:
        if conn is not None and not conn.closed:
            try:
                conn.rollback()
            except Exception:
                pass
        raise RefreshTokenDatabaseError("failed to rotate token") from None
    finally:
        _close_quietly(conn)


def revoke_family(family_id: uuid.UUID | str) -> None:
    """
    Revoke every non-revoked token in the given family.

    Idempotent. Used by logout, password change, and reuse detection.
    Acquires the family-level advisory lock FIRST, then updates. No
    token-level lock is taken; the family lock is the sole serialization
    point for revoke operations.

    Raises:
        RefreshTokenDatabaseError: if a database operation fails.
    """
    conn: Connection | None = None
    try:
        conn = get_auth_connection()
        with conn.cursor() as cur:
            _acquire_family_lock(cur, family_id)

            cur.execute(
                """
                UPDATE auth_session.refresh_tokens
                   SET revoked_at = clock_timestamp()
                 WHERE family_id = %s
                   AND revoked_at IS NULL
                """,
                (str(family_id),),
            )
        conn.commit()
    except psycopg.Error:
        if conn is not None and not conn.closed:
            try:
                conn.rollback()
            except Exception:
                pass
        raise RefreshTokenDatabaseError("failed to revoke family") from None
    finally:
        _close_quietly(conn)


def revoke_family_by_raw_token(raw_token: str) -> None:
    """
    Revoke every non-revoked token in the family identified by the given raw
    refresh token.

    Idempotent: if the raw token is unknown, it is a silent no-op. This is
    used by POST /auth/logout, where the cookie may already be invalid and
    a failure must not surface to the client.

    Lock order (family -> row) is preserved: the family_id is read without
    locking the token, the family lock is acquired, then the UPDATE runs
    under that lock. No row-level lock on the token is needed because the
    UPDATE targets the family, not the individual token.

    Raises:
        RefreshTokenDatabaseError: if a database operation fails. Unknown
            tokens are a no-op, not an error.
    """
    if not isinstance(raw_token, str) or not raw_token:
        return
    token_hash = hash_refresh_token(raw_token)

    conn: Connection | None = None
    try:
        conn = get_auth_connection()
        with conn.cursor() as cur:
            # Step 1: find the family_id without locking the token row.
            cur.execute(
                "SELECT family_id FROM auth_session.refresh_tokens WHERE token_hash = %s",
                (token_hash,),
            )
            row = cur.fetchone()
            if row is None:
                # Unknown token: nothing to revoke, silent no-op.
                conn.rollback()
                return
            family_id = row[0]

            # Step 2: acquire the family-level advisory lock.
            _acquire_family_lock(cur, family_id)

            # Step 3: revoke every non-revoked token in the family.
            cur.execute(
                """
                UPDATE auth_session.refresh_tokens
                   SET revoked_at = clock_timestamp()
                 WHERE family_id = %s
                   AND revoked_at IS NULL
                """,
                (str(family_id),),
            )
        conn.commit()
    except psycopg.Error:
        if conn is not None and not conn.closed:
            try:
                conn.rollback()
            except Exception:
                pass
        raise RefreshTokenDatabaseError("failed to revoke family") from None
    finally:
        _close_quietly(conn)


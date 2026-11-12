"""
app/core/jwt.py
================================================================================
SecureBiz Lab - JWT Access Token Issuance and Verification
================================================================================

Responsibilities:
    - Create HS256 access tokens (create_access_token).
    - Verify HS256 access tokens and their claims (verify_access_token).

This file MUST NOT contain:
    - The HS256 secret (loaded from Vault via app.core.vault.get_jwt_secret).
    - Refresh token logic (see app.services.refresh).
    - API routes or business logic.
    - Password hashing (see the login flow).

Scope note:
    verify_access_token() validates the JWT (signature, algorithm, required
    claims, format). It does NOT verify:
      - user account status (active/disabled),
      - organization membership,
      - permission grants,
      - token revocation.
    Those checks belong to the authentication dependency and to the database
    security layer (see app/api/dependencies.py and the auth_security schema).

Design Notes:
    - Only HS256 is allowed. The algorithm is not configurable, to prevent
      accidental 'none' or asymmetric algorithm substitution.
    - The signing secret is fetched from Vault via get_jwt_secret() and
      cached at the module level. Rotation is supported: a token signed with
      either current_kid or previous_kid is accepted.
    - All validation failures raise TokenValidationError (a ValueError
      subclass) with a generic message that never contains the token, the
      secret, or raw PyJWT exception content.

================================================================================
"""

# 1. Standard library
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

# 2. Third-party
import jwt  # PyJWT
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

# 3. Local
from app.core.config import settings
from app.core.vault import get_jwt_secret


# Only HS256 is allowed. Not configurable.
JWT_ALGORITHM = "HS256"

# Claims that must be present in every access token.
_REQUIRED_CLAIMS = ("sub", "iss", "aud", "iat", "exp", "jti", "token_type")

# Tolerated clock skew for iat/exp checks (seconds).
_CLOCK_SKEW_SECONDS = 30


class TokenValidationError(ValueError):
    """Raised when a JWT fails signature or claim validation."""


def _now_utc() -> datetime:
    """Return the current time in UTC (timezone-aware)."""
    return datetime.now(timezone.utc)


def _is_canonical_uuid(value: str) -> bool:
    """
    Return True iff value is the canonical lowercase 8-4-4-4-12 string form
    of a UUID.

    uuid.UUID() accepts non-canonical forms (uppercase, braces, no dashes).
    This helper rejects them, so that tokens produced and consumed by this
    codebase always use the same representation.
    """
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        return False
    return str(parsed) == value


def create_access_token(user_id: str) -> str:
    """
    Create a signed HS256 access token for the given user.

    Args:
        user_id: canonical UUID string of the authenticated user.

    Returns:
        The encoded JWT as a str.

    Raises:
        ValueError: if user_id is not a canonical UUID string.
        RuntimeError: if the Vault secret cannot be loaded.
    """
    if not _is_canonical_uuid(user_id):
        raise ValueError("user_id must be a canonical UUID string") from None

    current_secret, current_kid, _prev_secret, _prev_kid = get_jwt_secret()

    now = _now_utc()
    exp = now + timedelta(seconds=settings.JWT_ACCESS_TTL_SECONDS)

    claims: dict[str, Any] = {
        "sub": user_id,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
        "token_type": "access",
    }

    headers = {"kid": current_kid}

    return jwt.encode(
        claims,
        current_secret,
        algorithm=JWT_ALGORITHM,
        headers=headers,
    )


def verify_access_token(token: str) -> dict[str, Any]:
    """
    Verify an HS256 access token and return its validated claims.

    Supports rotation: a token signed with either the current_kid or the
    previous_kid is accepted. When no rotation is in progress, get_jwt_secret()
    returns previous_* as None; in that case only current_kid is accepted.

    This function validates the JWT itself. It does NOT check whether the user
    is active, whether the organization membership is valid, or whether the
    token has been revoked. Those checks belong to the authentication
    dependency and the database security layer.

    Args:
        token: the JWT string.

    Returns:
        The decoded and validated claims dict.

    Raises:
        TokenValidationError: on any signature or claim failure. The message
            never contains the token, the secret, or raw PyJWT exception
            content.
    """
    if not isinstance(token, str) or not token:
        raise TokenValidationError("token must be a non-empty string") from None

    current_secret, current_kid, prev_secret, prev_kid = get_jwt_secret()

    # Rotation consistency: if the Vault secret is configured inconsistently,
    # fail loudly instead of silently ignoring the previous key.
    if (prev_secret is None) != (prev_kid is None):
        raise RuntimeError(
            "Vault JWT secret: previous and previous_kid must be either both "
            "present or both absent"
        )

    key_map: dict[str, bytes] = {current_kid: current_secret}
    if prev_secret is not None and prev_kid is not None:
        key_map[prev_kid] = prev_secret

    # Peek at the unverified header to select the right key.
    try:
        unverified_header = jwt.get_unverified_header(token)
    except InvalidTokenError:
        raise TokenValidationError("invalid token header") from None

    header_alg = unverified_header.get("alg")
    if header_alg != JWT_ALGORITHM:
        raise TokenValidationError("unsupported algorithm in token header") from None

    kid = unverified_header.get("kid")
    if not isinstance(kid, str) or kid not in key_map:
        raise TokenValidationError("unknown or missing kid") from None

    key = key_map[kid]

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
            options={
                "require": list(_REQUIRED_CLAIMS),
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_sub": False,
            },
            leeway=timedelta(seconds=_CLOCK_SKEW_SECONDS),
        )
    except ExpiredSignatureError:
        raise TokenValidationError("token expired") from None
    except InvalidAudienceError:
        raise TokenValidationError("invalid audience") from None
    except InvalidIssuerError:
        raise TokenValidationError("invalid issuer") from None
    except InvalidSignatureError:
        raise TokenValidationError("invalid signature") from None
    except MissingRequiredClaimError:
        raise TokenValidationError("missing required claim") from None
    except InvalidTokenError:
        raise TokenValidationError("invalid token") from None

    # Explicit token_type check.
    if claims.get("token_type") != "access":
        raise TokenValidationError("token_type must be 'access'") from None

    # Explicit sub check (canonical UUID).
    sub = claims.get("sub")
    if not _is_canonical_uuid(sub):
        raise TokenValidationError("sub must be a canonical UUID string") from None

    # Explicit jti check (canonical UUID).
    jti = claims.get("jti")
    if not _is_canonical_uuid(jti):
        raise TokenValidationError("jti must be a canonical UUID string") from None

    # Explicit iat/exp consistency check.
    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise TokenValidationError("iat and exp must be integers") from None
    if exp <= iat:
        raise TokenValidationError("exp must be greater than iat") from None

    now_ts = int(_now_utc().timestamp())
    if iat > now_ts + _CLOCK_SKEW_SECONDS:
        raise TokenValidationError("iat is in the future") from None

    return claims

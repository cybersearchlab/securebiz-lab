"""
app/schemas/auth.py
================================================================================
SecureBiz Lab - Authentication Pydantic schemas
================================================================================

Responsibilities:
    - Define request/response models for /auth/login, /auth/refresh, /auth/logout.

This file MUST NOT contain:
    - Authentication logic (belongs to app.api.routes.auth).
    - Token issuance or verification (belongs to app.core.jwt).
    - Password verification (belongs to the login flow).

Design Notes:
    - email uses EmailStr. This is stricter than the database, which has no
      CHECK constraint on public.users.email. It enforces RFC-compliant format
      and length <= 254 before any SQL query.
    - EmailStr does NOT strip whitespace. Clients sending ' user@example.com '
      receive 422. This is intentional: a padded email indicates a client bug.
    - email-validator normalizes the domain part to lowercase. The local part
      is preserved. auth_private.authenticate() compares
      lower(email) = lower(p_email), so the composition is consistent.
================================================================================
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """POST /auth/login request body."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    """Successful authentication response. The refresh token travels in a cookie."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int

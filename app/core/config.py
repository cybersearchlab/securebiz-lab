"""
app/core/config.py
================================================================================
SecureBiz Lab - Application Configuration
================================================================================

Responsibilities:
    â€¢ Load environment variables at startup.
    â€¢ Validate the presence and format of critical configuration values.
    â€¢ Expose a single, immutable `settings` object for the rest of the app.

This file MUST NOT contain:
    â€¢ Database connections (see `database.py`).
    â€¢ Cryptographic keys or secrets (handled by Vault).
    â€¢ Business logic or API routes.

Security Note:
    In a Docker environment, environment variables are injected by Docker
    Compose. We explicitly do NOT load a `.env` file here to prevent
    accidental secret embedding in the container image (OWASP ASVS 2.6.1).
    The API will fail-fast at startup if any required variable is missing.

================================================================================
"""

# 1. Standard library
# (No standard library imports required)

# 2. Third-party
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.

    Attributes:
        DB_HOST (str): PostgreSQL hostname (e.g., 'db' in Docker).
        DB_PORT (int): PostgreSQL port. Must be between 1 and 65535.
        DB_NAME (str): PostgreSQL database name.
        DB_USER (str): PostgreSQL application user (e.g., 'securebiz_app').
        DB_PASSWORD (str): PostgreSQL application password.

    Design Note:
        All fields are required and must be non-empty (min_length=1).
        This enforces the "fail-fast" principle: if a variable is missing
        or empty (like DB_PASSWORD=""), the application will raise a
        ValidationError and refuse to start, rather than silently
        connecting with an empty password.
    """

    model_config = SettingsConfigDict(
        # Ignore extra variables injected by Docker (like HOSTNAME)
        extra="ignore",
        # Do not convert DB_HOST to db_host automatically
        case_sensitive=True,
    )

    DB_HOST: str = Field(..., min_length=1)
    DB_PORT: int = Field(5432, ge=1, le=65535)
    DB_NAME: str = Field(..., min_length=1)
    DB_USER: str = Field(..., min_length=1)
    DB_PASSWORD: str = Field(..., min_length=1)
    AUTH_DB_USER: str = Field(..., min_length=1)
    AUTH_DB_PASSWORD: str = Field(..., min_length=1)
    # JWT settings (non-secret; the HS256 secret lives in Vault).
    # These parameters are validated and non-secret, so they are configurable
    # via environment variables. The algorithm is NOT configurable: it is
    # hard-coded as HS256 in app/core/jwt.py.
    JWT_ISSUER: str = Field("securebiz-api", min_length=1)
    JWT_AUDIENCE: str = Field("securebiz-api", min_length=1)
    JWT_ACCESS_TTL_SECONDS: int = Field(900, ge=60, le=86400)
    REFRESH_TTL_DAYS: int = Field(7, ge=1, le=30)


# Singleton instance used throughout the application.
# Imported as: from app.core.config import settings
settings = Settings()

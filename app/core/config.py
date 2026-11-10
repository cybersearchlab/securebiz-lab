"""
app/core/config.py
================================================================================
SecureBiz Lab - Application Configuration
================================================================================

Responsibilities:
    • Load environment variables at startup.
    • Validate the presence and format of critical configuration values.
    • Expose a single, immutable `settings` object for the rest of the app.

This file MUST NOT contain:
    • Database connections (see `database.py`).
    • Cryptographic keys or secrets (handled by Vault).
    • Business logic or API routes.

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


# Singleton instance used throughout the application.
# Imported as: from app.core.config import settings
settings = Settings()

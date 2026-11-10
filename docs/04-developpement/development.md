# Development Guide

## Environment

Development is done on Windows 11 using PowerShell and Docker Desktop.
The commands in this guide must be executed from the repository root,
unless stated otherwise.

## Known Python Dependencies

The `requirements.txt` file currently contains:

```text
fastapi
uvicorn[standard]
psycopg[binary]
pydantic-settings
requests
cryptography
Note: For a reproducible project, versions will be pinned in a later step
after validating the dependency strategy (e.g., using pip freeze or pip-tools).

Application Configuration
app/core/config.py loads database settings from environment variables.
It uses pydantic-settings for strict validation.

Important Design Rule: There are no fallback values for critical fields.
If a required variable (like DB_USER) is missing or empty, the API will
raise a ValidationError at startup and refuse to run. This enforces
a fail-fast behavior and prevents running with an insecure configuration.

app/core/database.py provides get_database_connection() and
get_database_session(), which open a Psycopg connection with a limited timeout.

app/core/vault.py initializes the HashiCorp Vault Transit engine and
ensures that the securebiz-context Ed25519 cryptographic key exists at startup.

Currently Known Routes
GET /: Basic application information.

GET /health: Basic PostgreSQL connectivity check.

The documentation does not assume the existence of any other routes yet.
Business routes (/organizations, /users, /roles) will be added in
the next phase, with a middleware that installs the cryptographic context
before each request.

Contribution Rules
Make one limited, testable change at a time.

Explain commands before executing them.

Never include secrets in code or logs.

Add or adapt tests with each new feature.

Update the documentation when verified behavior changes.

Do not apply an unreviewed SQL migration.

Verify changes using the application role with limited privileges
(securebiz_app), not the superuser.

Database Migrations
SQL files are located in database/migrations/. The IAM migration
001_iam_multitenant_v8.sql has been applied with securebiz_user
(see CHANGELOG.md v0.3.0).

Security Rule: Do not execute migrations using the application account
used by the API (securebiz_app). The migration role (securebiz_user)
and the security function owner (securebiz_owner) must be separated from
the application role.

Vault Development Notes
Vault runs in -dev mode (-dev-root-token-id, -dev-listen-address).
This is not suitable for production.

The Ed25519 private key is non-exportable. If the Vault container is
recreated, a new key is generated and the old public key in
auth_security.public_keys becomes invalid. In development, re-register
the new key (see docs/06-tests/validation.md §3).

In production, Vault must be configured with persistent storage,
seal/unseal, mTLS, and audit logging.
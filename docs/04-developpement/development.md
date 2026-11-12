# Development Guide

## Environment

Development is done on Windows 11 using PowerShell and Docker Desktop.
The commands in this guide must be executed from the repository root,
unless stated otherwise.

## Known Python Dependencies

The `requirements.txt` file currently contains:

```text
fastapi==0.162.2
uvicorn[standard]==0.54.0
psycopg[binary]==3.3.8
pydantic-settings==2.16.2
requests==2.34.2
cryptography==50.0.2
pytest==8.3.4
httpx==0.28.1
PyJWT==2.10.1
argon2-cffi==25.1.0
email-validator==2.2.0

All versions are now pinned. The image securebiz-lab-api:latest is rebuilt with these packages. A Dockerfile change adds --timeout 120 --retries 5 and the Aliyun PyPI mirror to stabilize builds on slow networks.

Note: for new dependencies, use pip install inside the running container to test, then add the pinned version to requirements.txt and rebuild the image. A package installed only with pip install (without requirements.txt update + rebuild) is lost on container restart.

Application Configuration
app/core/config.py loads database and JWT settings from environment variables.
It uses pydantic-settings for strict validation.

Important Design Rule: There are no fallback values for critical fields.
If a required variable (like DB_USER) is missing or empty, the API will
raise a ValidationError at startup and refuse to run. This enforces
a fail-fast behavior and prevents running with an insecure configuration.

Configuration fields:

Database (business): DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD.

Database (authentication): AUTH_DB_USER, AUTH_DB_PASSWORD.

JWT: JWT_ISSUER (default securebiz-api), JWT_AUDIENCE (default securebiz-api), JWT_ACCESS_TTL_SECONDS (default 900), REFRESH_TTL_DAYS (default 7).

app/core/database.py provides:

get_raw_connection() — business role (securebiz_app).

get_auth_connection() — authentication role (securebiz_auth).

get_database_connection() — backward-compatible alias for get_raw_connection().

get_database_session() — context manager (commit/rollback guaranteed).

app/core/vault.py initializes the HashiCorp Vault Transit engine and ensures that the securebiz-context Ed25519 cryptographic key exists at startup. It also provides get_jwt_secret() which reads the JWT HS256 secret from Vault KV-v2 (secret/data/securebiz/jwt), caches it at module level, and never exposes it.

app/core/jwt.py provides:

create_access_token(user_id) — HS256, claims sub, iss, aud, iat, exp, jti, token_type="access", kid header.

verify_access_token(token) — validates signature, algorithm, iss, aud, exp, iat, sub, jti, token_type. Rotation support via kid.

app/services/refresh.py provides:

generate_refresh_token(), hash_refresh_token(token).

create_refresh_family(user_id, user_agent, ip) → (raw_token, family_id).

rotate_refresh_token(raw_token) → (new_raw, user_id). Reuse detection revokes the entire family and COMMITs before raising.

revoke_family(family_id).

revoke_family_by_raw_token(raw_token) — used by /auth/logout. Idempotent on unknown token.

Exceptions: RefreshTokenError(ValueError) for business validation (401), RefreshTokenDatabaseError(RuntimeError) for infrastructure (503).

app/schemas/auth.py provides LoginRequest (with EmailStr) and TokenResponse.

Currently Known Routes
GET / — Basic application information.

GET /health — Basic PostgreSQL connectivity check.

GET /users — List users in the current organization. Still uses debug headers (X-Debug-User-Id, X-Debug-Org-Id).

GET /organizations/me — Current organization. Still uses debug headers.

GET /roles — List roles in the current organization. Still uses debug headers.

POST /auth/login — Verify credentials, issue JWT + refresh cookie.

POST /auth/refresh — Rotate the refresh token, issue new JWT + new cookie.

POST /auth/logout — Revoke the refresh family, clear the cookie.

/openapi.json should return 8 paths. If it returns fewer, the API has not reloaded the last main.py change; restart the container with docker compose restart securebiz-api.

Migration of /users, /organizations/me, /roles to JWT authentication is planned (Priority 6). The routes will then require Authorization: Bearer <jwt> and X-Organization-Id, and return 401 (no JWT), 400 (no X-Organization-Id), or 403 (no active membership in the target organization).

Development Workflow
Making a code change
Inspect the file first.

Make one limited, testable change at a time.

If the file is on a bind-mounted volume (app/, scripts/, tests/), the container may auto-reload with uvicorn --reload. If not, restart the API container.

Verify via /openapi.json or a targeted test.

Adding a Python package
Install it temporarily in the running container: docker exec securebiz-api pip install <pkg>==<version>.

Add the pinned version to requirements.txt.

Rebuild the image: docker compose build api.

Recreate the container: docker compose up -d --force-recreate api.

Verify the import in the container: docker exec securebiz-api python -c "import <pkg>".

Do not skip the rebuild. A package installed only with pip install disappears on container restart.

Inspecting the database
All migrations and read-only inspections use securebiz_user (the migration admin). The application runtime uses securebiz_app for business tables and securebiz_auth for authentication tables.

powershell
# Read-only inspection
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT ... ;"

# Apply a migration (never with securebiz_app)
docker exec -i securebiz-postgres psql -v ON_ERROR_STOP=1 -U securebiz_user -d securebiz < database/migrations/00X_migration.sql
Testing authentication manually
powershell
# Login
$body = @{ email = "test-user@test.com"; password = "TestPassword!2026" } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri http://localhost:8000/auth/login -ContentType "application/json" -Body $body
$login.access_token

# Refresh (the cookie is sent automatically by the browser; with curl/Invoke-RestMethod, extract it from the Set-Cookie header)
# Logout
Invoke-RestMethod -Method Post -Uri http://localhost:8000/auth/logout
In tests (Python), use httpx.AsyncClient with ASGITransport(app=app), base_url="https://testserver", and pass the refresh cookie via headers={"Cookie": f"refresh_token={token}"} for replay scenarios. ASGITransport does not inject cookies set via cookies.set(). See docs/06-tests/verifications.md §8.

Contribution Rules
Make one limited, testable change at a time.

Explain commands before executing them.

Never include secrets in code or logs.

Add or adapt tests with each new feature.

Update the documentation when verified behavior changes.

Do not apply an unreviewed SQL migration.

Verify changes using the application role with limited privileges
(securebiz_app), not the superuser.

Never use securebiz_user (superuser) as the runtime account.

Never grant BYPASSRLS or SUPERUSER to runtime roles.

Never disable RLS or FORCE RLS to make a test pass.

For JWT-sensitive code, never log the token, the secret, the password hash, the user_id, or the jti. Only log the class of failure.

For SQL errors, use psycopg.Error and exc.diag.message_primary for classification, not str(exc).

In PowerShell scripts that call docker exec psql or docker cp, do not check $LASTEXITCODE (it is unreliable on stderr). Verify the DB state with SELECT or the file existence with Test-Path.

In PowerShell scripts, if $ErrorActionPreference is Stop, wrap the block in try/finally and use a local $ErrorActionPreference = "Continue" to avoid crashes on native stderr.

Database Migrations
SQL files are located in database/migrations/. Two migrations have been applied:

001_iam_multitenant_v8.sql — IAM schema, RLS, RBAC functions (v0.3.0).

002_auth_session.sql — auth_session schema, refresh_tokens table, get_user_status function (v0.4.0).

Security Rule: Do not execute migrations using the application account
used by the API (securebiz_app). The migration role (securebiz_user)
and the security function owner (securebiz_owner) must be separated from
the application role.

Migration files are not automatically applied on existing databases. The PostgreSQL entrypoint (/docker-entrypoint-initdb.d) runs only on first initialization. Apply new migrations manually with psql as securebiz_user, with ON_ERROR_STOP=1.

Migration 002 — what it does
Creates auth_session schema.

Creates auth_session.refresh_tokens (BYTEA hash, family_id, revoked_at, replaced_by, CHECK 32 bytes, CHECK expires_at > issued_at, UNIQUE token_hash).

Creates 3 indexes on user_id, family_id, expires_at.

Creates auth_session.get_user_status(UUID) (SECURITY DEFINER, owned by securebiz_owner).

Grants securebiz_auth SELECT, INSERT, UPDATE on refresh_tokens (no DELETE).

Grants securebiz_auth EXECUTE on get_user_status.

Revokes all from securebiz_app and PUBLIC.

Vault Development Notes
Vault runs in -dev mode (-dev-root-token-id, -dev-listen-address).
This is not suitable for production.

The Ed25519 private key is non-exportable. If the Vault container is
recreated, a new key is generated and the old public key in
auth_security.public_keys becomes invalid. In development, re-register
the new key (see docs/06-tests/verifications.md §3).

The JWT HS256 secret is stored in Vault KV-v2 at secret/data/securebiz/jwt. The dev root token is static (dev-only-root-token). It is too powerful for production. A restricted policy (read on transit/sign/securebiz-context, transit/keys/securebiz-context, secret/data/securebiz/jwt) is required.

init_vault_key() mounts the Transit engine and creates the key on startup. This is an admin operation mixed with runtime. In production, the API should use a restricted token that can only sign and read the secret, not mount engines or create keys.

In production, Vault must be configured with persistent storage,
seal/unseal, mTLS, and audit logging.

Troubleshooting
ModuleNotFoundError: No module named 'jwt' (or argon2, email_validator)
The container is running an image that does not have the Priority 5 packages. Rebuild:

powershell
docker compose build api
docker compose up -d --force-recreate api
/openapi.json returns fewer than 8 paths
The API is running an older main.py. Restart:

powershell
docker compose restart securebiz-api
pip install times out during docker compose build api
The Dockerfile already has --timeout 120 --retries 5 and the Aliyun mirror. If it still fails, the MTU of the Docker bridge may be too high. See docs/03-installation/setup.md.

docker exec psql writes to stderr and the PowerShell script stops
Wrap the block in try/finally and set $ErrorActionPreference = "Continue" locally. Do not check $LASTEXITCODE after psql; verify the DB state with SELECT.

Refresh test fails with "Refresh token required." instead of "Invalid refresh token."
The test client did not send the cookie. httpx.ASGITransport does not inject cookies set via cookies.set(). Use headers={"Cookie": f"refresh_token={token}"}.

text

## Ce qui a changé vs v0.3.0

| Section | Changement |
|---|---|
| **Known Python Dependencies** | 11 paquets avec versions épinglées (ajout PyJWT, argon2-cffi, email-validator). Note sur pip install temporaire + rebuild. |
| **Application Configuration** | Ajout `AUTH_DB_*`, `JWT_*`, `REFRESH_TTL_DAYS`. Ajout `get_auth_connection()`, `get_jwt_secret()`, `app/core/jwt.py`, `app/services/refresh.py`, `app/schemas/auth.py`. |
| **Currently Known Routes** | Ajout des 3 routes auth. Précision sur les IAM routes (debug headers). Note sur `--reload` vs restart. |
| **Development Workflow (nouveau)** | 3 sous-sections : code change, add package (avec rebuild), inspect DB. Test manuel d'auth avec `httpx.AsyncClient`. |
| **Contribution Rules** | 6 nouvelles règles : jamais `securebiz_user` runtime, jamais BYPASSRLS, jamais désactiver RLS, pas de log token/secret, `psycopg.Error` avec `diag.message_primary`, `$LASTEXITCODE` unreliable. |
| **Database Migrations** | Ajout migration `002_auth_session.sql` + section dédiée décrivant son contenu. |
| **Vault Development Notes** | Ajout du JWT secret dans Vault KV, root token trop puissant, `init_vault_key()` mixte. |
| **Troubleshooting (nouveau)** | 5 problèmes courants + solutions (ModuleNotFoundError, moins de 8 paths, timeout pip, psql stderr, cookie ASGITransport). |
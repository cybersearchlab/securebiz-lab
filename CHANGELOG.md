# Changelog

All notable changes to SecureBiz Lab are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/) and
the project adheres to [Semantic Versioning](https://semver.org/).

Dates reflect the milestones reported during development. Validation
evidence is preserved in the `docs/06-tests/` directory.

---

## [0.4.0] — 2026-11-12

### Added

- **Authentication database foundation** (migration `002_auth_session.sql`):
  - New schema `auth_session`.
  - `auth_session.refresh_tokens` table: `id`, `user_id`, `family_id`, `token_hash` (BYTEA, SHA-256, CHECK 32 bytes), `issued_at`, `expires_at` (CHECK > issued_at), `revoked_at`, `replaced_by` (FK auto-référente), `user_agent`, `ip_address` (INET).
  - 3 named constraints: `refresh_tokens_hash_length_check`, `refresh_tokens_expiration_check`, `refresh_tokens_unique_hash`.
  - 3 indexes: `idx_refresh_tokens_user_id`, `idx_refresh_tokens_family_id`, `idx_refresh_tokens_expires_at`.
  - `auth_session.get_user_status(UUID)` SECURITY DEFINER function (owned by `securebiz_owner`, `search_path=pg_catalog, pg_temp`).
  - `securebiz_auth` granted SELECT, INSERT, UPDATE on `refresh_tokens` (no DELETE; revocation is by UPDATE `revoked_at`).
  - `securebiz_auth` granted EXECUTE on `get_user_status`.
  - `securebiz_app` and PUBLIC excluded.
  - `securebiz_owner` granted USAGE on `auth_session` and SELECT on `refresh_tokens` (audit).

- **Dedicated authentication database connection**:
  - `app/core/database.py`: new `_connect(user, password)` helper, `get_raw_connection()` (securebiz_app), `get_auth_connection()` (securebiz_auth), `get_database_connection()` alias, `get_database_session()` context manager.
  - `app/core/config.py`: `AUTH_DB_USER`, `AUTH_DB_PASSWORD` fields.
  - `docker-compose.yml`: `AUTH_DB_USER`, `AUTH_DB_PASSWORD` environment variables.
  - `.env`: `AUTH_DB_PASSWORD` (64 hex chars).
  - TCP connection as `securebiz_auth` from the API container verified.

- **Vault KV-v2 JWT secret**:
  - Secret `secret/data/securebiz/jwt` provisioned (32 bytes hex, `current_kid`, `previous`/`previous_kid` for rotation).
  - `app/core/vault.py`: new `get_jwt_secret()` returning `(current_secret: bytes, current_kid: str, previous_secret: bytes | None, previous_kid: str | None)`, cached at module level.
  - `invalidate_jwt_secret_cache()` for tests and rotation.

- **JWT issuance and verification** (`app/core/jwt.py`):
  - `create_access_token(user_id)`: HS256, PyJWT 2.10.1, claims `sub`, `iss`, `aud`, `iat`, `exp`, `jti` (UUID4), `token_type="access"`, `kid` header.
  - `verify_access_token(token)`: rejects `alg` other than HS256 (including `none`, `RS256`), unknown or missing `kid`, wrong `iss`/`aud`, expired, wrong `token_type`, non-canonical `sub`/`jti`, missing required claim, tampered signature, `iat` in the future.
  - Rotation support: `current_kid` and `previous_kid` both accepted during the rotation window.
  - 18/18 unit tests passed.

- **Refresh token service** (`app/services/refresh.py`, rewritten):
  - `generate_refresh_token()`: opaque, 256 bits, `secrets.token_urlsafe(32)`.
  - `hash_refresh_token(token)`: SHA-256, 32 bytes, matching the CHECK constraint.
  - `create_refresh_family(user_id, user_agent, ip)`: inserts the first token, returns `(raw_token, family_id)`.
  - `rotate_refresh_token(raw_token)`: transactional rotation with `pg_advisory_xact_lock(hashtextextended(family_id::text, 0))` acquired before the row lock. On reuse detection, revokes the entire family and COMMITs before raising.
  - `revoke_family(family_id)`: idempotent, family-level advisory lock.
  - `revoke_family_by_raw_token(raw_token)`: new function used by `/auth/logout`. Silent no-op on unknown token.
  - Exception separation: `RefreshTokenError(ValueError)` for business validation (unknown, expired, revoked, reused, invalid state), `RefreshTokenDatabaseError(RuntimeError)` for infrastructure failures. The two do not inherit from each other, so `except RefreshTokenError` cannot swallow a DB failure.
  - Lock order: family first, row second, uniformly across the three functions. Prevents deadlock between concurrent rotation and revocation.

- **Authentication routes** (`app/api/routes/auth.py`):
  - `POST /auth/login`: Argon2id verify + dummy hash on unknown email + generic 401 on any credentials failure + `get_user_status()` check + JWT + refresh cookie. Cookie: `refresh_token`, HttpOnly, Secure, SameSite=Strict, Path=/auth, Max-Age=604800.
  - `POST /auth/refresh`: rotates the refresh token. If the user is no longer `active` after rotation, revokes the newly created token (`revoke_family_by_raw_token(new_raw)`) before returning 401. If JWT issuance fails after rotation, revokes `new_raw` before returning 503.
  - `POST /auth/logout`: revokes the refresh family and clears the cookie. Idempotent. Returns 503 on real DB failure (does not mask it as 200).

- **Pydantic schemas** (`app/schemas/auth.py`):
  - `LoginRequest(email: EmailStr, password: str = Field(min_length=1, max_length=256))`.
  - `TokenResponse(access_token, token_type="bearer", expires_in)`.

- **JWT dependencies** (`app/api/dependencies.py`):
  - `UserContext` frozen dataclass (`user_id`, `jti`).
  - `get_current_user(authorization: Header)`: extracts Bearer token, calls `verify_access_token()`. Exception mapping: `TokenValidationError` → 401, `RuntimeError` (Vault) → 503, any other `Exception` → 500 (never 503, never 401).
  - `get_authenticated_tenant_context(user, x_organization_id)`: same transaction lifecycle as `get_tenant_context()`, using the verified JWT identity + `X-Organization-Id`. SQL error classification: `psycopg.OperationalError` → 503; `psycopg.Error` with `diag.message_primary` in `{"Inactive or unauthorized user membership"}` → 403, in `{"Token expired", "Unknown or revoked signing key"}` → 503, everything else (including `"Token replay detected"` and `"Invalid Ed25519 signature"`) → 500.
  - Original `get_tenant_context()` (debug headers) kept untouched for backward compatibility.
  - `get_authenticated_tenant_context()` is implemented but not yet called by any route (Priority 6 migration pending).

- **`requirements.txt`**:
  - `PyJWT==2.10.1`
  - `argon2-cffi==25.1.0`
  - `email-validator==2.2.0`

- **Dockerfile**:
  - pip install with `--timeout 120 --retries 5` and Aliyun PyPI mirror for stable builds.

### Validated

- **Priority 5 functional tests — 9/9 passed** (12 November 2026):
  - P1 login OK → 200 + access_token + refresh cookie (F1).
  - P2 unknown email → 401 `"Invalid credentials."`.
  - P3 wrong password → 401 `"Invalid credentials."`.
  - P4 refresh with F1 cookie → 200, new cookie, same `family_id`, new JWT.
  - P5 replay of old F1 cookie → 401, F1 fully revoked (SQL-verified: `count(*) WHERE revoked_at IS NULL = 0`).
  - P6 new login → 200, F2 distinct from F1.
  - P7 logout with F2 cookie → 200, F2 revoked.
  - P8 logout without cookie → 200.
  - P11 disabled user refresh → 401, F3 revoked, user reactivated.
- **JWT unit tests (Bloc C)**: 18/18 passed (valid, alg=none, alg=RS256, wrong kid, wrong iss, wrong aud, expired, wrong token_type, non-canonical sub/jti, missing claim, tampered signature, create with non-canonical UUID).
- **Database state after Priority 5**: `credentials=1`, `refresh_tokens=0`, `active_tokens=0`, `user=active`.
- **API surface**: `/openapi.json` returns 8 paths (`/`, `/health`, `/users`, `/organizations/me`, `/roles`, `/auth/login`, `/auth/refresh`, `/auth/logout`).
- **End-to-end after rebuild**: login 200, access_token present, refresh cookie present.

### Changed

- `app/main.py`: `auth_router` registered after `organizations_router`, `users_router`, `roles_router`. `/openapi.json` now returns 8 paths.
- `app/core/config.py`: added `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_ACCESS_TTL_SECONDS`, `REFRESH_TTL_DAYS`.
- `app/core/vault.py`: added `get_jwt_secret()` and `invalidate_jwt_secret_cache()`.
- `app/api/dependencies.py`: added `UserContext`, `get_current_user()`, `get_authenticated_tenant_context()`, and the two classification frozensets `_REFUSAL_MESSAGES_403`, `_TRANSIENT_MESSAGES_503`.
- `Dockerfile`: pip install with extended timeout/retries and Aliyun mirror. The previous `pip install -r requirements.txt` remains the base, only the options changed.
- Docker image `securebiz-lab-api:latest` rebuilt with all Priority 5 packages. Verified after two `--force-recreate` cycles: `PyJWT 2.10.1`, `argon2-cffi 25.1.0`, `email-validator 2.2.0`, `httpx 0.28.1` are now persisted in the image (previously only in the running container).

### Fixed

- **`psycopg` error mapping in `get_current_user` and `get_authenticated_tenant_context`**: a `psycopg.Error` with a `diag.message_primary` matching a business refusal is mapped to 403, not 503. A programming bug or unexpected SQL anomaly is mapped to 500, not 503. A `RuntimeError` from `get_jwt_secret()` (Vault unreachable) is mapped to 503.
- **Refresh token reuse race condition**: the advisory lock `pg_advisory_xact_lock(hashtextextended(family_id::text, 0))` is acquired uniformly before any row lock in `rotate_refresh_token`, `revoke_family`, and `revoke_family_by_raw_token`. Prevents a concurrent rotation and revocation from leaving a newly inserted token active.
- **Refresh token replay on expired + revoked token**: `revoked_at` is checked before `is_expired` in `rotate_refresh_token`, so an expired + revoked token triggers family revocation instead of a generic "expired" response.
- **`RefreshTokenDatabaseError` separation**: introduced so that `except RefreshTokenError` in the auth routes cannot swallow a database failure as a 401.
- **`.env` corruption (v11 → v12)**: `VAULT_DEV_ROOT_TOKEN` was concatenated with `AUTH_DB_PASSWORD` because `Add-Content` was used without a trailing newline. Rebuilt using `[System.IO.File]::WriteAllLines()`. Documented as a pitfall.

### Known limitations

- Vault is running in `-dev` mode with the static root token `dev-only-root-token`. **Do not use in production.** A restricted Vault policy (read on `transit/sign/securebiz-context`, `transit/keys/securebiz-context`, `secret/data/securebiz/jwt`) is required for production.
- `init_vault_key()` mixes Vault provisioning (mount engine, create key) with runtime. Must be separated in production.
- `@app.on_event("startup")` is deprecated in FastAPI 0.109+. Migration to `lifespan=` is pending.
- JWT key rotation procedure (Vault KV `current`/`previous` kids) is not automated. The design supports it, no operational procedure exists yet.
- IAM routes (`/users`, `/organizations/me`, `/roles`) still use the debug-header path (`X-Debug-User-Id`, `X-Debug-Org-Id`). Migration to `get_authenticated_tenant_context()` is Priority 6.
- `tests/test_isolation.py` still uses debug headers. Migration to JWT is Priority 6 or 9.
- No provisioning endpoint or script for Argon2id password hashes. Only one test credential exists (manually created via `psql` as `securebiz_user`).
- `scripts/state_check.py` does not yet check `auth_session.refresh_tokens`, `get_user_status`, or `auth_private.credentials`. Extension is Priority 9.
- `securebiz_get_context()` is VOLATILE, not STABLE, which prevents plan-level caching in RLS policy evaluation.
- `auth_session.refresh_tokens` has RLS disabled intentionally (session store protected by strict ACLs, not a tenant table).
- `httpx.ASGITransport` does not inject cookies set via `cookies.set()`. Tests must use `headers={"Cookie": f"refresh_token={token}"}` for replay scenarios. Applies to both `httpx` and `httpx2`.

---

## [0.3.0] — 2026-11-10

### Added

- **Cryptographic context validation (end-to-end)**:
  - Ed25519 signature generated by HashiCorp Vault Transit (`securebiz-context` key).
  - Signature verified by PostgreSQL using `pgsodium.crypto_sign_verify_detached()`.
  - Public key registered in `auth_security.public_keys` (32 bytes, Ed25519).
- **Multi-tenant IAM schema** (`001_iam_multitenant_v8.sql`):
  - 7 business tables: `organizations`, `users`, `memberships`, `roles`, `permissions`, `membership_roles`, `role_permissions`.
  - Private schema `auth_private` for credentials (`auth_private.credentials`).
  - Security schema `auth_security` for keys, JTI, and transaction context.
  - `FORCE ROW LEVEL SECURITY` on all tenant-scoped tables.
- **Security functions** (owned by `securebiz_owner`, `SECURITY DEFINER`):
  - `auth_security.securebiz_install_context(payload, signature, kid)` — verifies claims, signature, statuses, and anti-replay, then installs the context bound to `pg_current_xact_id()`.
  - `auth_security.securebiz_get_context(field)` — returns the current transaction's `user_id` or `organization_id`.
  - `auth_security.app_has_permission(code)` — RBAC check against `membership_roles` and `role_permissions`.
  - `auth_private.authenticate(email)` — narrow authentication lookup (no direct table access for `securebiz_auth`).
  - `auth_security.securebiz_cleanup_context()` — marks the current context as cleaned.
  - `auth_security.securebiz_purge_expired_security_data()` — administrative purge of expired contexts and JTIs.
  - `auth_security.securebiz_register_public_key(kid, key)` — administrative registration of Ed25519 public keys.
  - `auth_security.securebiz_revoke_public_key(kid)` — administrative key revocation.
- **Row-Level Security policies** for `securebiz_app`:
  - `SELECT/INSERT/UPDATE/DELETE` per table, filtered by `organization_id`.
  - RBAC enforced via `app_has_permission('<code>')`.
  - System roles (`is_system = TRUE`) are protected from create/update/delete.
- **PostgreSQL roles** (validated attributes):
  - `securebiz_user`: SUPERUSER (migration admin only).
  - `securebiz_owner`: NOLOGIN, NOBYPASSRLS, owns security functions.
  - `securebiz_app`: LOGIN, NOSUPERUSER, NOBYPASSRLS (business API).
  - `securebiz_auth`: LOGIN, NOSUPERUSER, NOBYPASSRLS (authentication only).
- **Targeted column grants**:
  - `UPDATE(id)` on `users` and `organizations` for `securebiz_owner`.
  - `UPDATE(user_id)` on `memberships` for `securebiz_owner`.
  - Required to satisfy `FOR SHARE` row locks in `securebiz_install_context()`.

### Validated

- **End-to-end cryptographic flow**:
  - Payload signed by Vault (`{"iss":"securebiz-api","aud":"securebiz-postgres","sub":"<user>","org":"<org>","iat":...,"exp":...,"jti":...}`).
  - 64-byte Ed25519 signature verified by `pgsodium`.
  - `securebiz_install_context()` returned `True`.
  - `securebiz_get_context('user_id')` and `('organization_id')` returned the correct UUIDs.
  - Transaction rolled back cleanly (no test data persisted).
- **Vault → cryptography interoperability**: independent Python verification confirmed that Vault's Ed25519 signature matches the registered public key.
- **`pgsodium` Ed25519 availability**: `pgsodium.crypto_sign_verify_detached(bytea, bytea, bytea)` confirmed present in `pgsodium 3.1.9`.
- **RLS lock validation**: `SET LOCAL ROLE securebiz_owner` + `FOR SHARE` succeeded after targeted `UPDATE(column)` grants were added.
- **Role privilege audit**: `securebiz_owner` is NOLOGIN with no `BYPASSRLS`; `securebiz_app` and `securebiz_auth` have no elevated privileges.

### Changed

- `requirements.txt` now includes `cryptography` (for independent Ed25519 verification during tests).
- `docker-compose.yml` now includes the `vault` service (HashiCorp Vault 1.20).
- PostgreSQL base image rebuilt as `postgres:16-bookworm` with `pgsodium 3.1.9` compiled in a custom `postgres/Dockerfile`.
- `app/core/vault.py` added: initializes the Vault Transit engine and the `securebiz-context` Ed25519 key on API startup.
- `app/main.py`: `startup_event()` now calls `init_vault_key()`.

### Fixed

- **`pgsodium_trg_mask_update` event trigger conflict**: the trigger requires `shared_preload_libraries = 'pgsodium'` (not needed for Ed25519 verification). It is temporarily disabled via `ALTER EVENT TRIGGER ... DISABLE` in the migration, and will be revisited if column masking is ever required.
- **Config fail-fast**: `pydantic-settings` now rejects empty strings for `DB_USER` and `DB_PASSWORD` (OWASP ASVS 2.6.1).
- **BOM UTF-8 issue**: all Python source files are now saved without BOM. `.editorconfig` and `.vscode/settings.json` will be added in a later iteration.

### Known limitations

- Vault is running in `-dev` mode (`-dev-root-token-id`, `-dev-listen-address`). **Do not use in production.**
- No automated key rotation procedure for Ed25519 keys yet.
- `auth_private.authenticate()` is defined but not yet wired into FastAPI.
- Multi-tenant isolation tests (Pytest) are not yet automated.

---

## [0.2.0] — 2026-11-09

### Added

- Strict configuration validation via `pydantic-settings`.
- `Field(..., min_length=1)` on all required database settings.
- `Field(5432, ge=1, le=65535)` on `DB_PORT`.
- Fail-fast at startup: a missing or empty variable raises `ValidationError`.

### Changed

- `app/core/config.py` migrated from `os.getenv` with defaults to `pydantic-settings`.
- `app/core/database.py`: introduced `get_database_session()` context manager (commit/rollback guaranteed).
- `app/main.py`: `health_check()` now uses `get_database_session()`.

### Validated

- Negative test: `docker compose run --rm -e DB_USER= api ...` correctly raises `ValidationError: string_too_short`.
- `/health` returns `healthy / available / connected`.

---

## [0.1.0] — 2026-11-09

### Added

- FastAPI API with Uvicorn.
- PostgreSQL 16 service managed by Docker Compose.
- PostgreSQL persistence via the `securebiz_pgdata` Docker volume.
- `GET /` for basic information.
- `GET /health` executing a `SELECT 1` health check.
- Centralized configuration in `app/core/config.py`.
- Centralized PostgreSQL connection in `app/core/database.py`.
- Initial directory structure for `api`, `core`, `models`, `schemas`, and `services`.
- Creation of the limited PostgreSQL role `securebiz_app`.
- Initial project documentation.

### In preparation

- Multi-organization IAM migration (draft, not applied).
- Minimum privileges for the application role.
- Switch of the API to the limited application role.
- Authentication, authorization, and RLS policies.
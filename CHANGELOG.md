# Changelog

All notable changes to SecureBiz Lab are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/) and
the project adheres to [Semantic Versioning](https://semver.org/).

Dates reflect the milestones reported during development. Validation
evidence is preserved in the `docs/06-tests/` directory.

---

## [v0.6.0] — 2026-11-13 — Priority 10: Hygiene and deprecations

### Added

- `.gitattributes`: normalize text files to LF, preserve CRLF for
  PowerShell scripts (`*.ps1`, `*.psm1`), mark binary files.
- `scripts/init_vault.py`: new admin-only script that enables the Vault
  Transit engine and creates the Ed25519 signing key (idempotent).
  Must be run once before starting the API, and again after any Vault
  restart in -dev mode (inmem storage loses all keys).

### Changed

- `app/main.py`: replace deprecated `@app.on_event("startup")` with a
  `lifespan` context manager. `init_vault_key()` is no longer called at
  startup. The lifespan now logs a warning pointing to
  `scripts/init_vault.py`.
- `app/api/dependencies.py`: replace deprecated
  `HTTP_422_UNPROCESSABLE_ENTITY` with `HTTP_422_UNPROCESSABLE_CONTENT`
  in `_parse_uuid()`. Starlette 1.10.0 provides the new constant.
- `app/core/vault.py`: docstring of `init_vault_key()` updated to
  'ADMIN ONLY. Must be invoked from scripts/init_vault.py, NOT from the
  API runtime.'
- `.gitignore`: add `.env.backup-*` (protect .env backups) and `*.bak-*`
  (protect any timestamped backup file). Existing rules preserved,
  no duplicate.

### Removed

- `app/api/dependencies.py`: remove the historical `get_tenant_context()`
  function (debug-header dependency). No route, test, or script
  references it since Priority 6 migrated all IAM routes to
  `get_authenticated_tenant_context()`. It has been dead code since then.

### Verified

- 132 tests persisted (108 host + 24 container):
  - `test_isolation.py`: 4/4 (F2, container)
  - `test_isolation_users.py`: 4/4 (container)
  - `test_isolation_roles.py`: 4/4 (container)
  - `test_dependencies_lifecycle.py`: 10/10 (host)
  - `test_refresh_db.py`: 12/12 (container, real PostgreSQL)
  - `test_jwt.py`: 38/38 (host)
  - `test_refresh.py`: 31/31 (host)
  - `test_auth_routes.py`: 18/18 (host)
  - `test_provision_user.py`: 11/11 (host)
- 108 host tests pass with `-W error::DeprecationWarning`
  (no more `on_event is deprecated` or `HTTP_422_UNPROCESSABLE_ENTITY
  is deprecated` warnings).
- `scripts/init_vault.py` executed in the container with `-w /app +
  PYTHONPATH=/app`: exit code 0.
- `docker exec python -c 'from app.main import app'` -> OK (10 routes).
- `with psycopg.connect(...) as conn:` closes the connection on context
  exit (verified with psycopg 3.3.8).

### Changed behaviour

- The API no longer provisions Vault at startup. `init_vault_key()` must
  be called manually via `scripts/init_vault.py` before using the API.
  This is a fail-closed separation: the runtime role cannot mount a
  secrets engine or create a key. If Vault was not provisioned, requests
  that need signing return 503 instead of silently recreating a key.

### Known limitations

- `scripts/init_vault.py` performs administrative operations. It should
  be invoked with an admin-scoped token. Do NOT call it from the API
  runtime.
- `with psycopg.connect(...) as conn:` closes the connection on context
  exit (verified with psycopg 3.3.8). `scripts/provision_user.py`
  already relies on this behaviour; no `finally: conn.close()` is
  needed.

---
## [v0.5.1] — 2026-11-13 — Priority 9: Test coverage and state_check extension

### Added

- `tests/test_jwt.py`: 38 unit tests for `app/core/jwt.py`
  (create/verify, 18 positive + 20 negative cases). No Vault, no DB.
- `tests/test_refresh.py`: 31 unit tests for `app/services/refresh.py`
  (mocked DB). Covers generate, hash, create, rotate, revoke, exceptions.
- `tests/test_auth_routes.py`: 18 integration tests for
  `/auth/login`, `/auth/refresh`, `/auth/logout` (mocked services).
- `tests/test_provision_user.py`: 11 unit tests for
  `scripts/provision_user.py` (mocked Vault + DB). Real Argon2id hashing.
- `tests/conftest.py`: minimal environment variables for pytest
  (`Settings()`, `vault.py` module-level `VAULT_TOKEN` check).
- `tests/test_isolation.py` extended: 4 JWT isolation tests
  (executed in the container, 4/4 pass).
- `scripts/state_check.py` v4: 10 checks (was 6), including
  `auth_session.refresh_tokens`, `get_user_status` ACL + behavior,
  `credentials` count, `securebiz_provisioner` role, dynamic Vault
  public key read.

### Changed

- `scripts/state_check.py`: `EXPECTED_PUBKEY_HEX` removed (obsolete
  after Vault restart on 2026-11-12). Public key now read dynamically
  from Vault Transit and compared to PostgreSQL (WARN on divergence,
  no auto-resync).
- `scripts/state_check.py`: `_admin_ready()` centralizes degraded mode
  (SKIP when `DB_ADMIN_USER` or `DB_ADMIN_PASSWORD` missing).

### Fixed

- `auth_security.public_keys` manually resynced with Vault
  (`ccc071be...` → `757147f3...`) after Vault container restart
  (dev mode `inmem` regenerates the Ed25519 key).

### Known limitations

- `tests/test_isolation.py` requires the API container
  (`vault:8200`, `db:5432` are Docker-internal DNS names).
  On the Windows host, 3/4 tests fail (VAULT_ADDR unreachable).
- `tests/test_refresh.py` and `tests/test_auth_routes.py` mock the
  database; they do not validate real PostgreSQL behavior
  (advisory locks, RLS, constraints, concurrency).
- `state_check.py` remains read-only except `check_full_flow`
  (install_context + rollback).

---

## [v0.5.0] — 2026-11-12 (evening) — Priority 8: Argon2id provisioning

### Added

- PostgreSQL role `securebiz_provisioner` (NOLOGIN initially, INSERT-only
  on `auth_private.credentials`), created by migration
  `database/migrations/003_provisioner_role.sql`.
- Vault policy `provisioner-read` (read-only on
  `secret/data/securebiz/provisioner`), stored in
  `vault/policies/provisioner-read.hcl`.
- Script `scripts/set_provisioner_password.py`: one-shot bootstrap that
  reads the provisioner password from Vault and executes
  `ALTER ROLE securebiz_provisioner WITH LOGIN PASSWORD`. Fail-safe:
  any verification failure triggers `rollback_to_nologin()` with
  confirmation.
- Script `scripts/provision_user.py`: Argon2id credential provisioning
  using the `provisioner-script` Vault token (read-only), same Argon2id
  parameters as `app/api/routes/auth.py`.
- End-to-end provisioning test: throwaway user, login 200 with
  access_token, cleanup.

### Changed

- `POSTGRES_PASSWORD` in `.env` and PostgreSQL reset to a 48-character
  cryptographically-safe value (synchronized, SCRAM verified).
- Vault re-provisioned after container restart (inmem storage): JWT
  secret v3, provisioner secret v1, policy, token.

### Fixed

- API crash loop on `init_vault_key()` due to Vault container stopped
  (ExitCode 255, Docker DNS name `vault` not resolving).

---

## [0.4.0] — 2026-11-12 — Priority 5 and Priority 6: authentication, JWT, IAM routes

### Added

- **Authentication database foundation** (migration `002_auth_session.sql`):
  - New schema `auth_session`.
  - `auth_session.refresh_tokens` table: `id`, `user_id`, `family_id`,
    `token_hash` (BYTEA, SHA-256, CHECK 32 bytes), `issued_at`,
    `expires_at` (CHECK > issued_at), `revoked_at`, `replaced_by`
    (FK self-referencing), `user_agent`, `ip_address` (INET).
  - 3 named constraints: `refresh_tokens_hash_length_check`,
    `refresh_tokens_expiration_check`, `refresh_tokens_unique_hash`.
  - 3 indexes: `idx_refresh_tokens_user_id`, `idx_refresh_tokens_family_id`,
    `idx_refresh_tokens_expires_at`.
  - `auth_session.get_user_status(UUID)` SECURITY DEFINER function
    (owned by `securebiz_owner`, `search_path=pg_catalog, pg_temp`).
  - `securebiz_auth` granted SELECT, INSERT, UPDATE on `refresh_tokens`
    (no DELETE; revocation is by UPDATE `revoked_at`).
  - `securebiz_auth` granted EXECUTE on `get_user_status`.
  - `securebiz_app` and PUBLIC excluded.
  - `securebiz_owner` granted USAGE on `auth_session` and SELECT on
    `refresh_tokens` (audit).

- **Dedicated authentication database connection**:
  - `app/core/database.py`: `_connect(user, password)`,
    `get_raw_connection()` (`securebiz_app`), `get_auth_connection()`
    (`securebiz_auth`), `get_database_connection()` alias,
    `get_database_session()` context manager.
  - `app/core/config.py`: `AUTH_DB_USER`, `AUTH_DB_PASSWORD` fields.
  - `docker-compose.yml`: `AUTH_DB_USER`, `AUTH_DB_PASSWORD` env vars.
  - `.env`: `AUTH_DB_PASSWORD` (64 hex chars).
  - TCP connection as `securebiz_auth` from the API container verified.

- **Vault KV-v2 JWT secret**:
  - Secret `secret/data/securebiz/jwt` provisioned (32 bytes hex,
    `current_kid`, `previous`/`previous_kid` for rotation).
  - `app/core/vault.py`: `get_jwt_secret()` returning
    `(current_secret: bytes, current_kid: str, previous_secret: bytes | None,
    previous_kid: str | None)`, cached at module level.
  - `invalidate_jwt_secret_cache()` for tests and rotation.

- **JWT issuance and verification** (`app/core/jwt.py`):
  - `create_access_token(user_id)`: HS256, PyJWT 2.10.1, claims `sub`,
    `iss`, `aud`, `iat`, `exp`, `jti` (UUID4), `token_type="access"`,
    `kid` header.
  - `verify_access_token(token)`: rejects `alg` other than HS256
    (including `none`, `RS256`), unknown or missing `kid`, wrong
    `iss`/`aud`, expired, wrong `token_type`, non-canonical `sub`/`jti`,
    missing required claim, tampered signature, `iat` in the future.
  - Rotation support: `current_kid` and `previous_kid` both accepted
    during the rotation window.
  - 18/18 unit tests passed (Bloc C).

- **Refresh token service** (`app/services/refresh.py`, rewritten):
  - `generate_refresh_token()`: opaque, 256 bits,
    `secrets.token_urlsafe(32)`.
  - `hash_refresh_token(token)`: SHA-256, 32 bytes, matching the CHECK
    constraint.
  - `create_refresh_family(user_id, user_agent, ip)`: inserts the first
    token, returns `(raw_token, family_id)`.
  - `rotate_refresh_token(raw_token)`: transactional rotation with
    `pg_advisory_xact_lock(hashtextextended(family_id::text, 0))` acquired
    before the row lock. On reuse detection, revokes the entire family
    and COMMITs before raising.
  - `revoke_family(family_id)`: idempotent, family-level advisory lock.
  - `revoke_family_by_raw_token(raw_token)`: used by `/auth/logout`.
    Silent no-op on unknown token.
  - Exception separation: `RefreshTokenError(ValueError)` for business
    validation (unknown, expired, revoked, reused, invalid state),
    `RefreshTokenDatabaseError(RuntimeError)` for infrastructure
    failures. The two do not inherit from each other, so
    `except RefreshTokenError` cannot swallow a DB failure.
  - Lock order: family first, row second, uniformly across the three
    functions. Prevents deadlock between concurrent rotation and
    revocation.

- **Authentication routes** (`app/api/routes/auth.py`):
  - `POST /auth/login`: Argon2id verify + dummy hash on unknown email
    + generic 401 on any credentials failure + `get_user_status()` check
    + JWT + refresh cookie. Cookie: `refresh_token`, HttpOnly, Secure,
    SameSite=Strict, Path=/auth, Max-Age=604800.
  - `POST /auth/refresh`: rotates the refresh token. If the user is no
    longer `active` after rotation, revokes the newly created token
    (`revoke_family_by_raw_token(new_raw)`) before returning 401. If JWT
    issuance fails after rotation, revokes `new_raw` before returning 503.
  - `POST /auth/logout`: revokes the refresh family and clears the
    cookie. Idempotent. Returns 503 on real DB failure (does not mask it
    as 200).

- **Pydantic schemas** (`app/schemas/auth.py`):
  - `LoginRequest(email: EmailStr, password: str = Field(min_length=1,
    max_length=256))`.
  - `TokenResponse(access_token, token_type="bearer", expires_in)`.

- **JWT dependencies** (`app/api/dependencies.py`):
  - `UserContext` frozen dataclass (`user_id`, `jti`).
  - `get_current_user(authorization: Header)`: extracts Bearer token,
    calls `verify_access_token()`. Exception mapping:
    `TokenValidationError` → 401, `RuntimeError` (Vault) → 503, any other
    `Exception` → 500 (never 503, never 401).
  - `get_authenticated_tenant_context(user, x_organization_id)`: same
    transaction lifecycle as `get_tenant_context()`, using the verified
    JWT identity + `X-Organization-Id`. SQL error classification:
    `psycopg.OperationalError` → 503; `psycopg.Error` with
    `diag.message_primary` in `{"Inactive or unauthorized user membership"}`
    → 403, in `{"Token expired", "Unknown or revoked signing key"}` → 503,
    everything else (including `"Token replay detected"` and
    `"Invalid Ed25519 signature"`) → 500.
  - Original `get_tenant_context()` (debug headers) kept untouched for
    backward compatibility.

- **Priority 6 — IAM route migration**:
  - `/users`, `/organizations/me`, `/roles` migrated from
    `get_tenant_context` (debug headers) to
    `get_authenticated_tenant_context` (JWT + `X-Organization-Id`).
  - `tests/test_isolation.py` rewritten with `httpx.AsyncClient` +
    `ASGITransport` (no `TestClient`). 4 tests: 200 (own org), 403
    (cross-tenant), 401 (no JWT), 400 (no `X-Organization-Id`).
    Each login's refresh family is revoked via `/auth/logout` in an
    asserted `finally` block.

- **`requirements.txt`**: `PyJWT==2.10.1`, `argon2-cffi==25.1.0`,
  `email-validator==2.2.0`, `httpx==0.28.1`.

### Changed

- `app/main.py`: `auth_router` registered after `organizations_router`,
  `users_router`, `roles_router`. `/openapi.json` returns 8 paths.
- `app/core/config.py`: `JWT_ISSUER`, `JWT_AUDIENCE`,
  `JWT_ACCESS_TTL_SECONDS`, `REFRESH_TTL_DAYS`.
- `app/core/vault.py`: `get_jwt_secret()`, `invalidate_jwt_secret_cache()`.
- `app/api/dependencies.py`: `UserContext`, `get_current_user()`,
  `get_authenticated_tenant_context()`, `_REFUSAL_MESSAGES_403`,
  `_TRANSIENT_MESSAGES_503`.
- `Dockerfile`: pip install with extended timeout/retries and Aliyun
  PyPI mirror for stable builds. Docker image `securebiz-lab-api:latest`
  rebuilt with all Priority 5 packages. Verified after two
  `--force-recreate` cycles: `PyJWT 2.10.1`, `argon2-cffi 25.1.0`,
  `email-validator 2.2.0`, `httpx 0.28.1` are persisted in the image.

### Fixed

- **`psycopg` error mapping**: a `psycopg.Error` with a
  `diag.message_primary` matching a business refusal is mapped to 403,
  not 503. A programming bug or unexpected SQL anomaly is mapped to 500,
  not 503. A `RuntimeError` from `get_jwt_secret()` (Vault unreachable)
  is mapped to 503.
- **Refresh token reuse race condition**: the advisory lock
  `pg_advisory_xact_lock(hashtextextended(family_id::text, 0))` is
  acquired uniformly before any row lock in `rotate_refresh_token`,
  `revoke_family`, and `revoke_family_by_raw_token`.
- **Refresh token replay on expired + revoked token**: `revoked_at` is
  checked before `is_expired` in `rotate_refresh_token`.
- **`RefreshTokenDatabaseError` separation**: `except RefreshTokenError`
  in the auth routes cannot swallow a database failure as a 401.
- **`.env` corruption (v11 → v12)**: `VAULT_DEV_ROOT_TOKEN` was
  concatenated with `AUTH_DB_PASSWORD` because `Add-Content` was used
  without a trailing newline. Rebuilt using
  `[System.IO.File]::WriteAllLines()`.

### Known limitations

- Vault is running in `-dev` mode with the static root token
  `dev-only-root-token`. **Do not use in production.**
- `init_vault_key()` mixes Vault provisioning with runtime.
- `@app.on_event("startup")` is deprecated in FastAPI 0.109+. Migration
  to `lifespan=` is pending.
- JWT key rotation procedure (Vault KV `current`/`previous` kids) is not
  automated.
- `tests/test_isolation.py` still uses debug headers on the host
  (requires container).
- No provisioning endpoint or script for Argon2id password hashes was
  added in v0.4.0 (Priority 8).
- `scripts/state_check.py` did not yet check `auth_session.refresh_tokens`,
  `get_user_status`, or `auth_private.credentials` (Priority 9).
- `securebiz_get_context()` is VOLATILE, not STABLE.
- `auth_session.refresh_tokens` has RLS disabled intentionally.
- `httpx.ASGITransport` does not inject cookies set via `cookies.set()`.
  Tests must use `headers={"Cookie": f"refresh_token={token}"}`.

---
## [0.3.0] — 2026-11-10

### Added

- **Cryptographic context validation (end-to-end)**:
  - Ed25519 signature generated by HashiCorp Vault Transit
    (`securebiz-context` key).
  - Signature verified by PostgreSQL using
    `pgsodium.crypto_sign_verify_detached()`.
  - Public key registered in `auth_security.public_keys` (32 bytes,
    Ed25519).
- **Multi-tenant IAM schema** (`001_iam_multitenant_v8.sql`):
  - 7 business tables: `organizations`, `users`, `memberships`, `roles`,
    `permissions`, `membership_roles`, `role_permissions`.
  - Private schema `auth_private` for credentials
    (`auth_private.credentials`).
  - Security schema `auth_security` for keys, JTI, and transaction
    context.
  - `FORCE ROW LEVEL SECURITY` on all tenant-scoped tables.
- **Security functions** (owned by `securebiz_owner`,
  `SECURITY DEFINER`):
  - `auth_security.securebiz_install_context(payload, signature, kid)` —
    verifies claims, signature, statuses, and anti-replay, then installs
    the context bound to `pg_current_xact_id()`.
  - `auth_security.securebiz_get_context(field)` — returns the current
    transaction's `user_id` or `organization_id`.
  - `auth_security.app_has_permission(code)` — RBAC check against
    `membership_roles` and `role_permissions`.
  - `auth_private.authenticate(email)` — narrow authentication lookup
    (no direct table access for `securebiz_auth`).
  - `auth_security.securebiz_cleanup_context()` — marks the current
    context as cleaned.
  - `auth_security.securebiz_purge_expired_security_data()` —
    administrative purge of expired contexts and JTIs.
  - `auth_security.securebiz_register_public_key(kid, key)` —
    administrative registration of Ed25519 public keys.
  - `auth_security.securebiz_revoke_public_key(kid)` — administrative
    key revocation.
- **Row-Level Security policies** for `securebiz_app`:
  - `SELECT/INSERT/UPDATE/DELETE` per table, filtered by
    `organization_id`.
  - RBAC enforced via `app_has_permission('<code>')`.
  - System roles (`is_system = TRUE`) are protected from
    create/update/delete.
- **PostgreSQL roles** (validated attributes):
  - `securebiz_user`: SUPERUSER (migration admin only).
  - `securebiz_owner`: NOLOGIN, NOBYPASSRLS, owns security functions.
  - `securebiz_app`: LOGIN, NOSUPERUSER, NOBYPASSRLS (business API).
  - `securebiz_auth`: LOGIN, NOSUPERUSER, NOBYPASSRLS (authentication
    only).
- **Targeted column grants**:
  - `UPDATE(id)` on `users` and `organizations` for `securebiz_owner`.
  - `UPDATE(user_id)` on `memberships` for `securebiz_owner`.
  - Required to satisfy `FOR SHARE` row locks in
    `securebiz_install_context()`.

### Validated

- **End-to-end cryptographic flow**:
  - Payload signed by Vault
    (`{"iss":"securebiz-api","aud":"securebiz-postgres","sub":"<user>","org":"<org>","iat":...,"exp":...,"jti":...}`).
  - 64-byte Ed25519 signature verified by `pgsodium`.
  - `securebiz_install_context()` returned `True`.
  - `securebiz_get_context('user_id')` and `('organization_id')`
    returned the correct UUIDs.
  - Transaction rolled back cleanly (no test data persisted).
- **Vault → cryptography interoperability**: independent Python
  verification confirmed that Vault's Ed25519 signature matches the
  registered public key.
- **`pgsodium` Ed25519 availability**:
  `pgsodium.crypto_sign_verify_detached(bytea, bytea, bytea)` confirmed
  present in `pgsodium 3.1.9`.
- **RLS lock validation**: `SET LOCAL ROLE securebiz_owner` +
  `FOR SHARE` succeeded after targeted `UPDATE(column)` grants were
  added.
- **Role privilege audit**: `securebiz_owner` is NOLOGIN with no
  `BYPASSRLS`; `securebiz_app` and `securebiz_auth` have no elevated
  privileges.

### Changed

- `requirements.txt` now includes `cryptography` (for independent
  Ed25519 verification during tests).
- `docker-compose.yml` now includes the `vault` service (HashiCorp
  Vault 1.20).
- PostgreSQL base image rebuilt as `postgres:16-bookworm` with
  `pgsodium 3.1.9` compiled in a custom `postgres/Dockerfile`.
- `app/core/vault.py` added: initializes the Vault Transit engine and
  the `securebiz-context` Ed25519 key on API startup.
- `app/main.py`: `startup_event()` now calls `init_vault_key()`.

### Fixed

- **`pgsodium_trg_mask_update` event trigger conflict**: the trigger
  requires `shared_preload_libraries = 'pgsodium'` (not needed for
  Ed25519 verification). It is temporarily disabled via
  `ALTER EVENT TRIGGER ... DISABLE` in the migration.
- **Config fail-fast**: `pydantic-settings` now rejects empty strings
  for `DB_USER` and `DB_PASSWORD` (OWASP ASVS 2.6.1).
- **BOM UTF-8 issue**: all Python source files are now saved without
  BOM. `.editorconfig` and `.vscode/settings.json` will be added in a
  later iteration.

### Known limitations

- Vault is running in `-dev` mode (`-dev-root-token-id`,
  `-dev-listen-address`). **Do not use in production.**
- No automated key rotation procedure for Ed25519 keys yet.
- `auth_private.authenticate()` is defined but not yet wired into
  FastAPI.
- Multi-tenant isolation tests (Pytest) are not yet automated.

---

## [0.2.0] — 2026-11-09

### Added

- Strict configuration validation via `pydantic-settings`.
- `Field(..., min_length=1)` on all required database settings.
- `Field(5432, ge=1, le=65535)` on `DB_PORT`.
- Fail-fast at startup: a missing or empty variable raises
  `ValidationError`.

### Changed

- `app/core/config.py` migrated from `os.getenv` with defaults to
  `pydantic-settings`.
- `app/core/database.py`: introduced `get_database_session()` context
  manager (commit/rollback guaranteed).
- `app/main.py`: `health_check()` now uses `get_database_session()`.

### Validated

- Negative test: `docker compose run --rm -e DB_USER= api ...`
  correctly raises `ValidationError: string_too_short`.
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
- Initial directory structure for `api`, `core`, `models`, `schemas`,
  and `services`.
- Creation of the limited PostgreSQL role `securebiz_app`.
- Initial project documentation.

### In preparation

- Multi-organization IAM migration (draft, not applied).
- Minimum privileges for the application role.
- Switch of the API to the limited application role.
- Authentication, authorization, and RLS policies.
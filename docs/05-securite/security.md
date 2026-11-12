# Security, Controls, and Threat Model

## Objective

This page describes the security principles targeted by SecureBiz Lab.
It does not claim that all controls are already implemented, but it
distinguishes **verified controls** from **planned controls**.

## Principles

-   **Least Privilege**: Every component and account is granted only the necessary rights.
-   **Defense in Depth**: Combine application, database, infrastructure, and testing controls.
-   **Separation of Duties**: Distinguish between maintenance accounts, application accounts, and authentication accounts.
-   **Secret Protection**: Use environment variables or a dedicated secrets manager; never commit secrets to Git.
-   **Asymmetric Cryptography**: The private key used to sign context tokens is isolated in HashiCorp Vault. The API can only request signatures; it does not hold the secret.
-   **Server-side Validation**: Never trust data sent by the client.
-   **Traceability**: Log useful security events without logging secrets.
-   **Secure Failure**: Errors must not reveal sensitive internal details.

## Control Status

| Control | Documented Status |
| :--- | :--- |
| FastAPI Application | In place |
| PostgreSQL Connection | Verified |
| DB Health Check | In place |
| Strict Configuration (Fail-fast) | In place (`pydantic-settings`) |
| Vault Transit Integration | In place (Ed25519 key generation, non-exportable) |
| `pgsodium` Extension | Installed (v3.1.9, custom PostgreSQL image) |
| Ed25519 Signature Verification | **Verified end-to-end** (Vault → pgsodium) |
| `securebiz_app` SQL Role | Created (no elevated privileges, no `BYPASSRLS`) |
| `securebiz_owner` SQL Role | Created (NOLOGIN, no `BYPASSRLS`, owns security functions) |
| `securebiz_auth` SQL Role | Created (LOGIN, no elevated privileges) |
| `securebiz_provisioner` SQL Role | **Created** (LOGIN, INSERT only on `auth_private.credentials`, no SELECT/UPDATE/DELETE, no `BYPASSRLS`) |
| Minimal privileges for `securebiz_app` | **Granted** (migration V8) |
| Multi-tenant RLS Isolation | **Enabled and forced** on all tenant-scoped tables |
| RBAC in SQL | **In place** (`app_has_permission()`) |
| Anti-replay (`used_jti`) | **In place** (atomic `INSERT ... ON CONFLICT`) |
| Claim validation (`iss`, `aud`, `exp`, `jti`) | **In place** (max 60s lifetime) |
| Authentication database foundation | **In place** (`auth_session` schema, `refresh_tokens`, `get_user_status`) |
| Separate authentication role | **In place** (`securebiz_auth`, `get_auth_connection()`) |
| JWT HS256 secret in Vault KV-v2 | **In place** (`secret/data/securebiz/jwt`) |
| JWT issuance and verification | **In place** (`app/core/jwt.py`, 18/18 unit tests) |
| Argon2id password verification | **In place** (`argon2-cffi==25.1.0`, `time_cost=2`, `memory_cost=19456`) |
| Refresh token rotation and reuse detection | **In place** (`app/services/refresh.py`, advisory lock per family) |
| API authentication (`/auth/login`, `/auth/refresh`, `/auth/logout`) | **In place** (9/9 functional tests) |
| JWT dependencies (`get_current_user`, `get_authenticated_tenant_context`) | **In place** and **used** by all three IAM routes (Priority 6) |
| IAM routes migrated to JWT | **In place** (Priority 6, commit `a65f27b`) |
| Tenant isolation tests under JWT | **In place** (`tests/test_isolation.py`, 4/4 passed) |
| Vault provisioning policy | **In place** (`provisioner-read`, read-only on `secret/data/securebiz/provisioner`) |
| Argon2id provisioning scripts | **In place** (`scripts/set_provisioner_password.py`, `scripts/provision_user.py`, end-to-end test passed) |
| Provisioning credentials storage | **In place** (Vault KV-v2, never in `.env` or git) |
| Permission-based authorization (route-level middleware) | Planned (RLS enforces at DB level; no route middleware yet) |
| Audit Log | Planned |
| Automated Security Tests | **Partial** (Priority 6 isolation tests in `tests/`; Priority 5 and Priority 8 tests are manual only) |
| CI/CD with Security Checks | Planned |

## Verified Cryptographic Flow

The cryptographic chain has been **validated end-to-end** with `securebiz_app`. This is documented in detail in `docs/06-tests/validation.md` §4.

Summary of the proof:

1.  FastAPI requests a signature from Vault Transit (`securebiz-context` Ed25519 key).
2.  Vault returns a 64-byte signature over the exact JSON payload bytes.
3.  FastAPI transmits `payload`, `signature`, `kid` to PostgreSQL.
4.  `pgsodium.crypto_sign_verify_detached()` returns `True`.
5.  `securebiz_install_context()` validates claims and installs the context
    bound to `pg_current_xact_id()`.
6.  `securebiz_get_context('user_id')` and `('organization_id')` return the
    correct UUIDs.
7.  Transaction is rolled back (test data not persisted).

**The private key never leaves Vault.** An attacker who compromises
`securebiz_app` cannot forge a valid context.

## Verified Authentication Flow (v0.4.0)

The authentication chain has been **validated end-to-end** with 9/9 functional tests. This is documented in detail in `docs/06-tests/verifications.md` §6–§13.

Summary of the proof:

1.  Client sends `POST /auth/login` with email and password.
2.  `securebiz_auth` calls `auth_private.authenticate(email)` — returns `(user_id, password_hash, status)`.
3.  FastAPI verifies the password with Argon2id.
4.  `auth_session.get_user_status(user_id)` re-checks the user status (`active` required).
5.  `create_access_token(user_id)` issues an HS256 JWT with `kid` (rotation-ready).
6.  `create_refresh_family(user_id, ...)` stores a SHA-256 hash of an opaque 256-bit token, returns `(raw_token, family_id)`.
7.  The raw refresh token is set as an `HttpOnly`, `Secure`, `SameSite=Strict` cookie on `/auth`, `Max-Age=604800` (7 days).
8.  On `POST /auth/refresh`, the token is rotated: old row revoked (`revoked_at`), new row inserted, `replaced_by` chain maintained. Advisory lock per `family_id` serializes concurrent operations.
9.  On reuse detection (`revoked_at IS NOT NULL` for the presented token), the entire family is revoked and COMMITed before the 401 is returned.
10. On `POST /auth/logout`, `revoke_family_by_raw_token(raw_token)` revokes the family and clears the cookie. Idempotent.

**The refresh token is never stored in plaintext.** Only its SHA-256 hash is persisted. Reuse detection prevents stolen tokens from being used after rotation.

**The JWT secret never leaves Vault.** `get_jwt_secret()` reads it from Vault KV-v2 and caches it in memory. No `.env` file, no source code, no logs.

## Risks and Mitigations

### Secrets

The `.env` file must be ignored by Git and protected on the development
machine. An `.env.example` file without secret values can document the
required variables. **Vault holds the Ed25519 private key and the JWT HS256 secret; neither is ever stored in `.env` or in PostgreSQL.**

### PostgreSQL Application Account

The initialization superuser account (`securebiz_user`) must not be used
by the API. The `securebiz_app` role has the required privileges (granted
via migration V8) and is used by the API. Its attributes have been audited:
`NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`.

The `securebiz_owner` role is NOLOGIN and has no `BYPASSRLS`. It is used
only via `SECURITY DEFINER` functions. The `securebiz_auth` role is
dedicated to authentication and cannot read the business tables directly.

New in v0.4.0: the `securebiz_auth` role has `SELECT, INSERT, UPDATE` (no `DELETE`) on `auth_session.refresh_tokens`, and `EXECUTE` on `auth_session.get_user_status(UUID)`. It has no `USAGE` on `auth_security` and no table privilege on `auth_private.credentials`. It cannot read `public.users` directly.

### Password Hashes

Password hashes are stored in `auth_private.credentials`, a schema that
is **not accessible to `securebiz_app`**. Only the `auth_private.authenticate(email)`
function (owned by `securebiz_owner`, `SECURITY DEFINER`) can read them.
This function is granted only to `securebiz_auth`.

Password hashes must never be included in API responses. The login flow
uses Argon2id for verification with parameters `time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16`. A dummy Argon2id hash is computed at import time and used to equalize timing when the email is unknown (prevents enumeration).

### JWT

JWT is HS256 with PyJWT 2.10.1. The secret is read from Vault KV-v2 (not from `.env`). Claims validated: `iss`, `aud`, `exp`, `iat`, `sub` (canonical UUID), `jti` (canonical UUID), `token_type == "access"`. The `kid` header selects the correct key (rotation support: `current_kid` and `previous_kid` accepted during the rotation window).

**Only HS256 is allowed.** The algorithm is hard-coded, not configurable, to prevent accidental `none` or asymmetric algorithm substitution. The `alg` header is verified before decoding.

All validation failures raise `TokenValidationError` (a `ValueError` subclass) with a generic message that never contains the token, the secret, or raw PyJWT content.

### Refresh Tokens

Refresh tokens are opaque 256-bit values (`secrets.token_urlsafe(32)`). Only their SHA-256 hash (32 bytes) is stored in `auth_session.refresh_tokens.token_hash` (BYTEA, CHECK 32 bytes). The raw token is returned to the client once (as a cookie) and never persisted.

Cookie attributes: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/auth`, `Max-Age=604800` (7 days). The cookie is never exposed to JavaScript.

Rotation: on every use, the old token is revoked (`revoked_at`), a new token is inserted, and the `replaced_by` chain is maintained. Reuse detection: if the presented token has `revoked_at IS NOT NULL`, the entire family is revoked and COMMITed before the 401 is returned.

Concurrency: `pg_advisory_xact_lock(hashtextextended(family_id::text, 0))` is acquired before any row lock in `rotate_refresh_token`, `revoke_family`, and `revoke_family_by_raw_token`. Uniform lock order (family first, row second) prevents deadlock.

Exception separation: `RefreshTokenError` (ValueError) for business validation failures (unknown, expired, revoked, reused, invalid state) → 401. `RefreshTokenDatabaseError` (RuntimeError) for infrastructure failures → 503. The two do not inherit from each other, so `except RefreshTokenError` cannot swallow a DB failure.

### Row-Level Security (RLS)

RLS is **enabled and forced** on all tenant-scoped tables (`organizations`,
`users`, `memberships`, `roles`, `membership_roles`, `role_permissions`).
Policies filter rows by `securebiz_get_context('organization_id')` and
enforce RBAC via `app_has_permission('<code>')`.

A tenant context defined by a custom SQL variable (`SET app.current_org_id`)
is **not** a verified identity. If an attacker gains the ability to execute
arbitrary SQL under the application role, they could modify this context.

**Mitigation:** SecureBiz Lab uses a **cryptographically signed context**
instead of SQL variables. The context is bound to `pg_current_xact_id()`
(a native `xid8` transaction identifier) and verified by `pgsodium` before
RLS policies apply.

Superusers and roles with `BYPASSRLS` can still bypass RLS. This is why
isolation tests must be performed with `securebiz_app`, not with an
administrator account. `securebiz_app` and `securebiz_auth` have no
`BYPASSRLS` attribute.

### System Role Protection

A trigger (`roles_system_protection`) prevents `securebiz_app` from:
- Creating a role with `is_system = TRUE`.
- Promoting an existing role to `is_system = TRUE`.
- Modifying or deleting a system role.

Administrative creation of system roles remains possible via migration
scripts executed by `securebiz_user`.

### Error Mapping (new in v0.4.0)

The `get_current_user` dependency maps:
- `TokenValidationError` → 401 (invalid token).
- `RuntimeError` (Vault unreachable) → 503.
- Any other `Exception` → 500 (never 503, never 401). A programming bug is not an infrastructure failure.

The `get_authenticated_tenant_context` dependency maps:
- `psycopg.OperationalError` → 503 (DB unavailable).
- `psycopg.Error` with `diag.message_primary = "Inactive or unauthorized user membership"` → 403.
- `psycopg.Error` with `diag.message_primary = "Token expired"` or `"Unknown or revoked signing key"` → 503.
- All other `psycopg.Error` (including `"Token replay detected"` and `"Invalid Ed25519 signature"`) → 500.

The auth routes (`/auth/*`) map:
- `RefreshTokenError` (business validation) → 401.
- `RefreshTokenDatabaseError` (infrastructure) → 503.
- `psycopg.Error` (login, refresh) → 503.
- `RuntimeError` (Vault) → 503.
- Generic 401 on any credentials failure (no distinction between unknown email and wrong password).

Logging: no token, no secret, no password hash, no `user_id`, no `jti`. Only the class of failure.

## Security Tests to Implement

The following tests are planned (Pytest roadmap):

-   An unauthenticated user cannot access protected resources.
-   A user from one organization cannot read data from another.
-   A signed context with an invalid or tampered signature is rejected by PostgreSQL.
-   A signed context with an expired `exp` claim is rejected.
-   A signed context with a reused `jti` is rejected (anti-replay).
-   A suspended member loses access.
-   A suspended organization loses access.
-   Roles cannot be assigned across organization boundaries.
-   A user cannot grant themselves permissions.
-   A user cannot promote themselves to system role.
-   Sensitive fields (e.g., password hashes) are never returned by the API.
-   SQL queries use parameters and never concatenate untrusted input.
-   Errors do not reveal secrets, connection strings, or internal stack traces to the client.

New in v0.4.0:

-   JWT with `alg=none` is rejected.
-   JWT with `alg=RS256` is rejected (algorithm confusion).
-   JWT with tampered signature is rejected.
-   JWT with wrong `kid` is rejected.
-   JWT with expired `exp` is rejected.
-   JWT with wrong `iss` or `aud` is rejected.
-   JWT with `token_type != "access"` is rejected.
-   JWT with non-canonical `sub` or `jti` is rejected.
-   Refresh token reuse detection: replayed token triggers full family revocation.
-   Refresh token rotation preserves `family_id`.
-   Disabled user cannot refresh (401, family revoked).
-   Logout revokes the family.
-   Logout without cookie is idempotent (200).
-   IAM routes return 401 without JWT (after Priority 6 migration).
-   IAM routes return 400 without `X-Organization-Id` (after Priority 6 migration).
-   IAM routes return 403 when the JWT user has no active membership in the target organization (after Priority 6 migration).

## Known Limitations

-   **Vault in `-dev` mode**: acceptable for the lab, not for production.
-   **Vault root token `dev-only-root-token`**: too powerful for production. A restricted policy (read on `transit/sign/securebiz-context`, `transit/keys/securebiz-context`, `secret/data/securebiz/jwt`) is required.
-   **`init_vault_key()` mixes Vault provisioning (mount engine, create key) with runtime**: must be separated in production.
-   **`@app.on_event("startup")` is deprecated in FastAPI 0.109+**: migration to `lifespan=` is pending.
-   **No automated key rotation**: JWT secret supports `current`/`previous` kids in Vault KV, Ed25519 supports `kid`, but no operational rotation procedure exists.
-   **IAM routes (`/users`, `/organizations/me`, `/roles`) still use debug headers**: migration to JWT is Priority 6.
-   **No provisioning endpoint for Argon2id hashes**: only one test credential exists.
-   **`scripts/state_check.py` does not cover `auth_session`**: extension is Priority 9.
-   **`pgsodium_trg_mask_update` event trigger disabled**: only Ed25519 verification is used, not column masking.
-   **`securebiz_get_context()` is VOLATILE, not STABLE**: prevents plan-level caching in RLS policy evaluation.
-   **`auth_session.refresh_tokens` has RLS disabled**: intentional (session store protected by strict ACLs, not a tenant table).
-   **`httpx.ASGITransport` does not inject cookies set via `cookies.set()`**: tests must use explicit `Cookie` header for replay scenarios. Applies to both `httpx` and `httpx2`.
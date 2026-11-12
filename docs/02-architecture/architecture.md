# Technical Architecture

## 1. Currently Deployed Architecture

The prototype uses three Docker Compose services:

| Service | Technology | Responsibility |
| :--- | :--- | :--- |
| `api` | Python, FastAPI, Uvicorn | Expose HTTP routes, orchestrate cryptography, install the transaction context, issue and verify JWTs. |
| `db` | PostgreSQL 16 Bookworm + `pgsodium` | Store data, verify Ed25519 signatures, enforce Row-Level Security, store refresh token hashes. |
| `vault` | HashiCorp Vault (Transit + KV-v2 engines) | Securely store the Ed25519 private key and sign contexts; store the JWT HS256 secret. The private key **never leaves Vault**. The JWT secret is read at startup and cached in memory. |

Inter-container communication uses the Docker Compose network. Known host ports:
- `127.0.0.1:8000` → API (FastAPI)
- `127.0.0.1:5433` → PostgreSQL
- `127.0.0.1:8200` → Vault

The `securebiz_pgdata` volume persists PostgreSQL data beyond the container lifecycle.

## 2. Health and Initialization Flow

### 2.1 Health check

The `GET /health` route opens a PostgreSQL connection via Psycopg, executes `SELECT 1`, and returns a healthy status if the query succeeds.

### 2.2 Vault initialization

When the API starts, `init_vault_key()` ensures:
1. The Vault Transit engine is enabled at `transit/`.
2. An Ed25519 key named `securebiz-context` exists (created with `exportable: false`).

The private key **never leaves Vault**. It cannot be exported, even by an administrator.

### 2.3 JWT secret loading (v0.4.0)

When the API issues or verifies a JWT, `get_jwt_secret()` reads the HS256 secret from Vault KV-v2 at `secret/data/securebiz/jwt` and caches it at module level. The secret is never written to `.env`, source code, or logs. `invalidate_jwt_secret_cache()` clears the cache for rotation or tests.

The Vault KV secret supports rotation via `current`/`current_kid` and `previous`/`previous_kid`. The JWT verifier accepts both `current_kid` and `previous_kid`, so a rotation window is possible.

### 2.4 Provisioning flow (v0.5.0)

Priority 8 introduced a dedicated provisioning workflow for creating Argon2id
credentials. It is separated from the API runtime: the API cannot write to
`auth_private.credentials`, and the provisioning role is not used by the
FastAPI application.

#### Actors

| Actor | Responsibility |
| :--- | :--- |
| `securebiz_provisioner` | Dedicated PostgreSQL role. `INSERT` only on `auth_private.credentials`. No `SELECT`, `UPDATE`, `DELETE`. Not used by the API. |
| Vault KV-v2 | Stores the provisioner database password at `secret/data/securebiz/provisioner` (key `db_password`). |
| Vault policy `provisioner-read` | Grants `read` only on the provisioner secret path. Attached to a dedicated token (`provisioner-script`, TTL 8h, max 24h). |
| `scripts/set_provisioner_password.py` | One-shot bootstrap. Reads the provisioner password from Vault (root token), then executes `ALTER ROLE securebiz_provisioner WITH LOGIN PASSWORD`. Fail-safe: any verification failure triggers `rollback_to_nologin()`. |
| `scripts/provision_user.py` | Recurring provisioning. Uses the `provisioner-script` token, reads the password from Vault, hashes the new user password with Argon2id, and inserts the credential as `securebiz_provisioner`. |

#### Flow

text
Operator (Windows host or inside securebiz-api)
  |
  v
scripts/provision_user.py
  |  (1) read VAULT_TOKEN from environment (provisioner-script token)
  |  (2) GET secret/data/securebiz/provisioner -> db_password
  |  (3) getpass or --generate -> plain password
  |  (4) Argon2id hash (same params as app/api/routes/auth.py)
  |  (5) INSERT INTO auth_private.credentials (user_id, password_hash)
  |      as securebiz_provisioner (host=db, port=5432)
  v
PostgreSQL (auth_private.credentials)
  |
  v
(optional) POST /auth/login -> 200 with access_token

#### Execution context

The provisioning scripts use the Docker-internal DNS names (`vault:8200`,
`db:5432`). They MUST be executed inside the `securebiz-api` container:

text
docker cp scripts/provision_user.py securebiz-api:/tmp/provision_user.py
docker exec -it -e VAULT_TOKEN=<provisioner-script-token> \
    -w /app securebiz-api python /tmp/provision_user.py --user-id <uuid> [--generate]
docker exec securebiz-api rm -f /tmp/provision_user.py

The Windows host cannot reach `vault:8200` or `db:5432` directly (Docker
Desktop WSL2 networking). Host execution is not supported.

#### Argon2id parameters

The provisioning script uses the same parameters as
`app/api/routes/auth.py` (single source of truth):

python
PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

#### Security properties

- The provisioner database password never leaves Vault.
- The new user password is never logged or displayed (except with
  `--generate`, where it is shown once on stdout with a warning).
- The password hash is never logged or displayed.
- PostgreSQL errors are translated to generic messages:
  `unique_violation` → credential already exists,
  `foreign_key_violation` → user_id does not exist,
  `insufficient_privilege` → role misconfigured,
  other → generic database error.
- The role `securebiz_provisioner` is created `NOLOGIN` (fail-closed) and
  activated only via the bootstrap script.

#### Known limitation

Vault runs in dev mode with `inmem` storage. A restart of the Vault
container loses all secrets (JWT, provisioner password, policy, token).
Re-provisioning is currently manual.

## 3. Code Organization

-   `app/main.py`: FastAPI entry point, base routes, and startup events. Registers `organizations_router`, `users_router`, `roles_router`, `auth_router`.
-   `app/core/config.py`: Strict configuration loading and validation (Pydantic, fail-fast on missing variables). Includes DB, AUTH_DB, JWT, and refresh TTL settings.
-   `app/core/database.py`: Psycopg connection creation and transaction management. Provides `get_raw_connection()` (business role), `get_auth_connection()` (auth role), `get_database_session()` (context manager).
-   `app/core/vault.py`: Vault Transit initialization, Ed25519 key management, JWT secret loading from Vault KV-v2.
-   `app/core/jwt.py`: JWT HS256 issuance and verification with rotation support.
-   `app/services/context_signing.py`: Builds and signs the canonical tenant context payload.
-   `app/services/refresh.py`: Refresh token generation, hashing, rotation, reuse detection, family revocation. Advisory lock per `family_id` for concurrency safety.
-   `app/api/dependencies.py`: `get_tenant_context` (debug headers, legacy), `get_current_user` (JWT), `get_authenticated_tenant_context` (JWT + `X-Organization-Id`).
-   `app/api/routes/auth.py`: `/auth/login`, `/auth/refresh`, `/auth/logout`.
-   `app/api/routes/`: Business endpoints (`organizations`, `users`, `roles`), still using debug headers (Priority 6 migration pending).
-   `app/schemas/auth.py`: `LoginRequest`, `TokenResponse`.
-   `app/models/`, `app/schemas/`, `app/services/`: Prepared for future domain logic.
-   `database/init/`: SQL initialization scripts (`pgsodium` extension).
-   `database/migrations/`: SQL migration scripts (`001_iam_multitenant_v8.sql`, `002_auth_session.sql`).

## 4. Cryptographic Architecture (Validated)

The multi-tenant model includes **7 business tables** (`organizations`, `users`, `memberships`, `roles`, `permissions`, `membership_roles`, `role_permissions`) and **private schemas**:

- `auth_private.credentials` (password hashes, isolated from the business API)
- `auth_security.public_keys` (Ed25519 public keys registered from Vault)
- `auth_security.transaction_context` (per-transaction identity context, linked to `xid8`)
- `auth_security.used_jti` (anti-replay protection)
- `auth_session.refresh_tokens` (v0.4.0 — SHA-256 hashes of opaque refresh tokens, `family_id`, `revoked_at`, `replaced_by`, `expires_at`; not RLS-enabled, protected by strict ACLs)

### 4.1 Cryptographic flow (validated end-to-end)

```text
Client (FastAPI)
│
├── 1. Receives identity (JWT or session)
├── 2. Requests a signature from Vault Transit
│   └── Private key Ed25519 (inside Vault only)
├── 3. Sends (payload + signature) to PostgreSQL
│
▼
PostgreSQL 16
│
├── 4. pgsodium.crypto_sign_verify_detached(public_key)
├── 5. Validates claims (iss, aud, exp, jti, statuses)
├── 6. Verifies user ↔ org membership
├── 7. Installs context: (txid xid8, user_id, org_id)
│
▼
RLS (Row-Level Security)
│
└── 8. Automatically filters rows by organization_id

4.2 Validation evidence
The full flow has been validated by an end-to-end test executed with securebiz_app:

Payload signed by Vault: {"iss":"securebiz-api","aud":"securebiz-postgres","sub":"<user>","org":"<org>","iat":...,"exp":...,"jti":...}

Signature length: 64 bytes (Ed25519)

securebiz_install_context() returns True

securebiz_get_context('user_id') returns the correct UUID

securebiz_get_context('organization_id') returns the correct UUID

Transaction rolled back (no test data persisted)

This proves that:

Vault can sign claims without exposing the private key.

pgsodium can verify Ed25519 signatures with the registered public key.

The context is correctly bound to pg_current_xact_id() and cannot be forged by securebiz_app.

RLS policies can read the context via securebiz_get_context().

5. Authentication Architecture (v0.4.0)
5.1 JWT access tokens
The API issues HS256 JWTs with PyJWT 2.10.1.

Element	Value
Algorithm	HS256 (hard-coded, not configurable)
Secret	Vault KV-v2 secret/data/securebiz/jwt
Claims	sub, iss, aud, iat, exp, jti, token_type="access"
Lifetime	JWT_ACCESS_TTL_SECONDS (default 900s = 15 min)
kid header	Yes (rotation support via current_kid / previous_kid)
verify_access_token() rejects:

any algorithm other than HS256 (including none and RS256),

unknown or missing kid,

wrong iss or aud,

expired exp,

token_type other than "access",

non-canonical sub or jti UUID,

missing required claim,

tampered signature,

iat in the future (with 30s leeway).

All validation failures raise TokenValidationError (a ValueError subclass) with a generic message that never contains the token, the secret, or raw PyJWT content.

5.2 Refresh tokens
Refresh tokens are opaque 256-bit values (secrets.token_urlsafe(32)). Only their SHA-256 hash is stored in auth_session.refresh_tokens.token_hash (BYTEA, CHECK 32 bytes).

Element	Value
Format	Opaque, 256 bits
Storage	SHA-256 hash (32 bytes) in auth_session.refresh_tokens
Lifetime	REFRESH_TTL_DAYS (default 7 days)
Transport	Cookie refresh_token — HttpOnly, Secure, SameSite=Strict, Path=/auth, Max-Age=604800
Rotation	On every use (replaced_by chain)
Reuse detection	Family revoked, COMMIT before 401
Family	family_id UUID shared across rotations
Concurrency: pg_advisory_xact_lock(hashtextextended(family_id::text, 0)) is acquired before any row lock in rotate_refresh_token, revoke_family, and revoke_family_by_raw_token. Uniform lock order (family first, row second) prevents deadlock.

Exception separation: RefreshTokenError(ValueError) for business validation (unknown, expired, revoked, reused, invalid state) → 401. RefreshTokenDatabaseError(RuntimeError) for infrastructure failures → 503. The two do not inherit from each other, so except RefreshTokenError cannot swallow a DB failure.

5.3 Authentication flow (validated 9/9 tests)
text
Client
│
├── POST /auth/login (email, password)
│   ├── securebiz_auth: auth_private.authenticate(email)
│   ├── Argon2id verify (argon2-cffi 25.1.0)
│   ├── auth_session.get_user_status(user_id) → must be 'active'
│   ├── create_access_token(user_id) → HS256 JWT
│   └── create_refresh_family(user_id, ...) → (raw_token, family_id)
│       └── Set-Cookie: refresh_token (HttpOnly, Secure, SameSite=Strict)
│
├── POST /auth/refresh (cookie)
│   ├── rotate_refresh_token(raw) → (new_raw, user_id)
│   ├── get_user_status(user_id) → if not 'active', revoke new_raw + 401
│   └── Set-Cookie: new refresh_token, new JWT
│
└── POST /auth/logout (cookie)
    ├── revoke_family_by_raw_token(raw) → revoke entire family
    └── Delete-Cookie: refresh_token
5.4 Authentication dependencies
get_current_user(authorization: Header):

Extracts Bearer <token>.

Calls verify_access_token(token).

Exception mapping: TokenValidationError → 401, RuntimeError (Vault) → 503, any other Exception → 500 (never 503, never 401).

Returns UserContext(user_id, jti).

Logs only the class of failure. Never logs token, secret, user_id, or jti.

get_authenticated_tenant_context(user, x_organization_id: Header):

Same transaction lifecycle as get_tenant_context().

Uses user.user_id (from JWT) and x_organization_id (from header).

SQL error classification via psycopg.Error.diag.message_primary:

"Inactive or unauthorized user membership" → 403.

"Token expired" / "Unknown or revoked signing key" → 503.

Everything else (including "Token replay detected" and "Invalid Ed25519 signature") → 500.

psycopg.OperationalError → 503 (DB unavailable).

Implemented and compiled, but not yet used by any route (Priority 6 migration pending).

6. Organization Isolation (RLS)
PostgreSQL Row-Level Security is enabled and forced on all tenant-scoped tables (organizations, users, memberships, roles, membership_roles, role_permissions).

6.1 Policy model
securebiz_owner (NOLOGIN) owns the security functions (securebiz_install_context, securebiz_get_context, app_has_permission, auth_private.authenticate, auth_session.get_user_status).

securebiz_owner has owner_*_policy (ALL, TRUE) on every business table, plus targeted UPDATE(column) grants to satisfy FOR SHARE locks.

securebiz_app (LOGIN) has strictly scoped SELECT/INSERT/UPDATE/DELETE policies that filter by securebiz_get_context('organization_id') and check app_has_permission('<permission_code>').

securebiz_auth (LOGIN) has no direct table access. It calls auth_private.authenticate(email), auth_session.get_user_status(user_id), and reads/writes auth_session.refresh_tokens (SELECT, INSERT, UPDATE; no DELETE).

6.2 Anti-forgery guarantee
Even if securebiz_app is compromised, an attacker cannot forge a valid context because:

The context is signed by Vault (private key never in PostgreSQL).

The context is bound to pg_current_xact_id() (per-transaction).

securebiz_install_context() rejects replays via used_jti.

securebiz_install_context() rejects expired tokens and invalid iss/aud.

The JWT authentication and the signed tenant context are two separate mechanisms. A valid JWT proves the user's identity to the API. A signed tenant context proves the API's origin to PostgreSQL. Neither replaces the other.

7. PostgreSQL Role Separation
Role	Attributes	Purpose
securebiz_user	SUPERUSER, LOGIN	Migration admin. Must not be used by the API.
securebiz_owner	NOLOGIN, NOBYPASSRLS	Owns security functions. Used only via SECURITY DEFINER.
securebiz_app	LOGIN, NOSUPERUSER, NOBYPASSRLS	Business API. Restricted by RLS + RBAC.
securebiz_auth	LOGIN, NOSUPERUSER, NOBYPASSRLS	Authentication only. Calls auth_private.authenticate(), auth_session.get_user_status(), and accesses auth_session.refresh_tokens.
8. Known Limitations and Accepted Debt
Vault in -dev mode: The current Vault container uses -dev-root-token-id and -dev-listen-address. This is acceptable for the lab but must not be used in production. Production requires a real Vault cluster with sealed/unseal, mTLS, and audit logging.

Vault root token too powerful: dev-only-root-token can do anything. In production, the API must use a restricted token policy (read on transit/sign/securebiz-context, transit/keys/securebiz-context, secret/data/securebiz/jwt).

init_vault_key() mixes admin and runtime operations: it mounts the Transit engine and creates the key on startup. In production, the API should only sign and read, not mount engines or create keys.

@app.on_event("startup") deprecated: FastAPI 0.109+ recommends lifespan=. Migration pending.

pgsodium event trigger disabled: The trigger pgsodium_trg_mask_update is disabled because it requires shared_preload_libraries = 'pgsodium' (not needed for Ed25519 signature verification). Revisit if column masking is used.

Public key rotation and JWT secret rotation: The design supports multiple keys via kid (Ed25519) and current/previous kids (JWT). No automated rotation procedure exists.

IAM routes not yet migrated to JWT: /users, /organizations/me, /roles still use debug headers (X-Debug-User-Id, X-Debug-Org-Id). Migration is Priority 6.

No provisioning endpoint: only one test credential exists (auth_private.credentials).

securebiz_get_context() is VOLATILE, not STABLE: prevents plan-level caching in RLS policy evaluation.

auth_session.refresh_tokens has RLS disabled: intentional (session store protected by strict ACLs, not a tenant table).

9. Next Steps
Migrate IAM routes (/users, /organizations/me, /roles) to get_authenticated_tenant_context() (JWT + X-Organization-Id).

Update tests/test_isolation.py to use JWT + X-Organization-Id.

Implement a provisioning endpoint or script for Argon2id password hashes.

Add automated multi-tenant isolation tests under JWT.

Extend scripts/state_check.py to cover auth_session.refresh_tokens, get_user_status, auth_private.credentials.

Integrate DevSecOps tools (Bandit, pip-audit, OWASP ZAP, GitHub Actions).

Migrate @app.on_event("startup") to lifespan=.

Separate Vault provisioning from runtime.

Implement a restricted Vault token policy for production.

text

## Ce qui a changé vs v0.3.0

| Section | Changement |
|---|---|
| **§1 Deployed Architecture** | Vault : ajout `KV-v2 engines`, stockage du JWT secret. API : ajout `issue and verify JWTs`. DB : ajout `store refresh token hashes`. |
| **§2.3 (nouveau)** | JWT secret loading : `get_jwt_secret()`, cache, rotation `current`/`previous`. |
| **§3 Code Organization** | Ajout `app/core/jwt.py`, `app/services/refresh.py`, `app/schemas/auth.py`, `app/api/routes/auth.py`. Précision sur `main.py` (4 routers), `config.py` (JWT/refresh TTL), `database.py` (auth connection), `vault.py` (JWT secret), `dependencies.py` (3 dépendances). |
| **§4 Business Tables** | Ajout `auth_session.refresh_tokens` dans les schemas privés. |
| **§5 Authentication Architecture (nouveau)** | 4 sous-sections : JWT access tokens, refresh tokens, auth flow (9/9 tests), auth dependencies. |
| **§6 Organization Isolation** | Ajout `auth_session.get_user_status` et `auth_session.refresh_tokens` dans le modèle de policy. Précision : JWT et signed tenant context = 2 mécanismes séparés. |
| **§7 PostgreSQL Role Separation** | Mise à jour `securebiz_auth` : `get_user_status`, `refresh_tokens`. |
| **§8 Known Limitations** | 6 nouvelles limitations : Vault token, `init_vault_key` mixte, `@app.on_event` déprécié, key rotation (JWT + Ed25519), IAM routes, provisioning, `VOLATILE`, RLS disabled. |
| **§9 Next Steps** | 9 items (contre 5 en v0.3.0) : migration IAM routes, update tests, provisioning endpoint, tests isolation sous JWT, extend state_check, DevSecOps, lifespan, Vault separation, restricted Vault policy. |
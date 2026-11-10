# Technical Architecture

## 1. Currently Deployed Architecture

The prototype uses three Docker Compose services:

| Service | Technology | Responsibility |
| :--- | :--- | :--- |
| `api` | Python, FastAPI, Uvicorn | Expose HTTP routes, orchestrate cryptography, install the transaction context. |
| `db` | PostgreSQL 16 Bookworm + `pgsodium` | Store data, verify Ed25519 signatures, enforce Row-Level Security. |
| `vault` | HashiCorp Vault (Transit engine) | Securely store the Ed25519 private key and sign contexts. The private key **never leaves Vault**. |

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

## 3. Code Organization

-   `app/main.py`: FastAPI entry point, base routes, and startup events.
-   `app/core/config.py`: Strict configuration loading and validation (Pydantic, fail-fast on missing variables).
-   `app/core/database.py`: Psycopg connection creation and transaction management.
-   `app/core/vault.py`: Vault Transit initialization and Ed25519 key management.
-   `app/api/routes/`: Prepared for business endpoints (`organizations`, `users`, `roles`, etc.).
-   `app/models/`, `app/schemas/`, `app/services/`: Prepared for future domain logic.
-   `database/init/`: SQL initialization scripts (`pgsodium` extension).
-   `database/migrations/`: SQL migration scripts (`001_iam_multitenant_v8.sql`).

## 4. Cryptographic Architecture (Validated)

The multi-tenant model includes **7 business tables** (`organizations`, `users`, `memberships`, `roles`, `permissions`, `membership_roles`, `role_permissions`) and **3 security tables** in private schemas:
- `auth_private.credentials` (password hashes, isolated from the business API)
- `auth_security.public_keys` (Ed25519 public keys registered from Vault)
- `auth_security.transaction_context` (per-transaction identity context, linked to `xid8`)
- `auth_security.used_jti` (anti-replay protection)

### 4.1 Cryptographic flow (validated end-to-end)

Client (FastAPI)
│
├── 1. Receives identity (JWT or session)
├── 2. Requests a signature from Vault Transit
│ └── Private key Ed25519 (inside Vault only)
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

text

### 4.2 Validation evidence

The full flow has been **validated by an end-to-end test** executed with `securebiz_app`:

- Payload signed by Vault: `{"iss":"securebiz-api","aud":"securebiz-postgres","sub":"<user>","org":"<org>","iat":...,"exp":...,"jti":...}`
- Signature length: 64 bytes (Ed25519)
- `securebiz_install_context()` returns `True`
- `securebiz_get_context('user_id')` returns the correct UUID
- `securebiz_get_context('organization_id')` returns the correct UUID
- Transaction rolled back (no test data persisted)

This proves that:
- Vault can sign claims without exposing the private key.
- `pgsodium` can verify Ed25519 signatures with the registered public key.
- The context is correctly bound to `pg_current_xact_id()` and cannot be forged by `securebiz_app`.
- RLS policies can read the context via `securebiz_get_context()`.

## 5. Organization Isolation (RLS)

PostgreSQL Row-Level Security is **enabled and forced** on all tenant-scoped tables (`organizations`, `users`, `memberships`, `roles`, `membership_roles`, `role_permissions`).

### 5.1 Policy model

- **`securebiz_owner`** (NOLOGIN) owns the security functions (`securebiz_install_context`, `securebiz_get_context`, `app_has_permission`, `auth_private.authenticate`).
- **`securebiz_owner`** has `owner_*_policy` (ALL, TRUE) on every business table, plus targeted `UPDATE(column)` grants to satisfy `FOR SHARE` locks.
- **`securebiz_app`** (LOGIN) has strictly scoped `SELECT/INSERT/UPDATE/DELETE` policies that filter by `securebiz_get_context('organization_id')` and check `app_has_permission('<permission_code>')`.
- **`securebiz_auth`** (LOGIN) has no direct table access. It only calls `auth_private.authenticate(email)`.

### 5.2 Anti-forgery guarantee

Even if `securebiz_app` is compromised, an attacker **cannot forge a valid context** because:
1. The context is signed by Vault (private key never in PostgreSQL).
2. The context is bound to `pg_current_xact_id()` (per-transaction).
3. `securebiz_install_context()` rejects replays via `used_jti`.
4. `securebiz_install_context()` rejects expired tokens and invalid `iss`/`aud`.

## 6. PostgreSQL Role Separation

| Role | Attributes | Purpose |
| :--- | :--- | :--- |
| `securebiz_user` | SUPERUSER, LOGIN | Migration admin. Must **not** be used by the API. |
| `securebiz_owner` | NOLOGIN, NOBYPASSRLS | Owns security functions. Used only via `SECURITY DEFINER`. |
| `securebiz_app` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Business API. Restricted by RLS + RBAC. |
| `securebiz_auth` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Authentication only. Calls `auth_private.authenticate()`. |

## 7. Known Limitations and Accepted Debt

- **Vault in `-dev` mode**: The current Vault container uses `-dev-root-token-id` and `-dev-listen-address`. This is acceptable for the lab but **must not be used in production**. Production requires a real Vault cluster with sealed/unseal, mTLS, and audit logging.
- **`pgsodium` event trigger disabled**: The trigger `pgsodium_trg_mask_update` is disabled because it requires `shared_preload_libraries = 'pgsodium'` (not needed for Ed25519 signature verification). This will be revisited if we ever use column masking.
- **Public key rotation**: The current design supports multiple keys via `kid`, but no automated rotation procedure is implemented yet.
- **`auth_private` is not yet used by FastAPI**: The login flow (`auth_private.authenticate`) is defined but not yet wired into the API.

## 8. Next Steps

1. Build FastAPI business routes (`/organizations`, `/users`, `/roles`) with a middleware that installs the context before each request.
2. Implement authentication (login, Argon2 password hashing, JWT emission).
3. Add automated multi-tenant isolation tests (Pytest).
4. Integrate DevSecOps tools (Bandit, pip-audit, OWASP ZAP, GitHub Actions).
5. Update `README.md`, `CHANGELOG.md`, `ROADMAP.md` with the validated architecture.
# SecureBiz Lab

[![SecureBiz Lab CI](https://github.com/cybersearchlab/securebiz-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersearchlab/securebiz-lab/actions/workflows/ci.yml)

**Security Assessment & DevSecOps for Business Applications**

> Document status: v0.6.0 — November 13, 2026
> Project status: Technical prototype — cryptographic architecture validated, authentication layer implemented, 132 automated tests (108 host + 24 container)

## 1. Overview

SecureBiz Lab is a laboratory project designed to demonstrate a structured approach to securing business applications. It serves as a practical sandbox to explore API security, Identity and Access Management (IAM), database security, multi-organization isolation, and DevSecOps practices.

The project is developed incrementally. The documentation systematically distinguishes between **verified features**, **ongoing work**, and **future objectives**.

## 2. Current Verified State

### 2.1 Infrastructure

- **API**: Python 3.12, FastAPI, Uvicorn.
- **Database**: PostgreSQL 16 (Bookworm) with `pgsodium 3.1.9` compiled in a custom image.
- **Cryptography**: HashiCorp Vault 1.20 (Transit + KV-v2 engines) with a **non-exportable Ed25519 key**.
- **Orchestration**: Docker Compose.

### 2.2 Cryptographic flow (validated end-to-end)

The full chain has been **proven by a real test** executed with `securebiz_app`:

| Step | Component | Result |
| :--- | :--- | :--- |
| 1. Sign claims | Vault Transit (`securebiz-context`) | 64-byte Ed25519 signature |
| 2. Verify signature | PostgreSQL + `pgsodium` | `True` |
| 3. Install context | `securebiz_install_context()` | Context bound to `pg_current_xact_id()` |
| 4. Read context | `securebiz_get_context('user_id')` / `('organization_id')` | Correct UUIDs |
| 5. Rollback | Transactional test | No test data persisted |

**The private key never leaves Vault.** Even an attacker with `securebiz_app` credentials cannot forge a valid context.

### 2.3 Applied IAM schema

The migration `001_iam_multitenant_v8.sql` has been executed:

- **7 business tables**: `organizations`, `users`, `memberships`, `roles`, `permissions`, `membership_roles`, `role_permissions`.
- **Private schema** `auth_private` (credentials, isolated from the business API).
- **Security schema** `auth_security`:
  - `public_keys` (Ed25519 keys registered from Vault).
  - `used_jti` (anti-replay).
  - `transaction_context` (per-transaction identity, linked to `xid8`).
- **RLS** enabled and forced on all tenant-scoped tables.
- **RBAC** enforced in SQL (`app_has_permission()`).

The migration `002_auth_session.sql` has also been executed:

- **Session schema** `auth_session`:
  - `refresh_tokens` (opaque refresh tokens, SHA-256 hashes, families, rotation, reuse detection).
  - `get_user_status(UUID)` SECURITY DEFINER function.

### 2.4 PostgreSQL roles

| Role | Attributes | Purpose |
| :--- | :--- | :--- |
| `securebiz_user` | SUPERUSER, LOGIN | Migration admin. Not used by the API. |
| `securebiz_owner` | NOLOGIN, NOBYPASSRLS | Owns security functions (`SECURITY DEFINER`). |
| `securebiz_app` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Business API. |
| `securebiz_auth` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Authentication only. |

### 2.5 Authentication layer (implemented in v0.4.0)

The following authentication features are implemented and verified by 9/9 functional tests (P1–P8, P11):

| Feature | Status |
| :--- | :--- |
| JWT HS256 issuance (`create_access_token`) | Implemented, 18/18 unit tests passed |
| JWT HS256 verification (`verify_access_token`) | Implemented, rejects `alg=none`, `RS256`, wrong `kid`, wrong `iss`/`aud`, expired, tampered signature |
| HS256 secret storage | Vault KV-v2 (`secret/data/securebiz/jwt`) |
| Argon2id password verification | Implemented (`argon2-cffi==25.1.0`, `time_cost=2`, `memory_cost=19456`) |
| Refresh token generation | Opaque 256-bit, SHA-256 hashed |
| Refresh token rotation | Implemented, `family_id` preserved, `replaced_by` chain |
| Refresh token reuse detection | Implemented, entire family revoked on replay |
| `POST /auth/login` | Implemented (200 + JWT + refresh cookie, 401 generic on failure) |
| `POST /auth/refresh` | Implemented (200 + rotated cookie, 401 + revocation if user disabled) |
| `POST /auth/logout` | Implemented (200, idempotent) |
| `get_current_user()` dependency | Implemented (Bearer JWT → `UserContext`) |
| `get_authenticated_tenant_context()` dependency | Implemented (JWT + `X-Organization-Id` → signed tenant context) |

**Not yet migrated**: the IAM routes (`/users`, `/organizations/me`, `/roles`) still use the development debug-header path (`X-Debug-User-Id`, `X-Debug-Org-Id`). Migration to `get_authenticated_tenant_context()` is planned for Priority 6.

### 2.6 Automated test coverage

As of v0.6.0, **132 automated tests** are persisted in `tests/`:

| File | Tests | Type | Verified |
| :--- | ---: | :--- | :--- |
| `test_jwt.py` | 38 | Host (mocked) | 38/38 |
| `test_refresh.py` | 31 | Host (mocked) | 31/31 |
| `test_auth_routes.py` | 18 | Host (mocked) | 18/18 |
| `test_provision_user.py` | 11 | Host (mocked) | 11/11 |
| `test_dependencies_lifecycle.py` | 10 | Host (mocked) | 10/10 |
| `test_isolation.py` (F2) | 4 | Container | 4/4 |
| `test_isolation_users.py` | 4 | Container | 4/4 |
| `test_isolation_roles.py` | 4 | Container | 4/4 |
| `test_refresh_db.py` | 12 | Container (real PostgreSQL) | 12/12 |

**Total: 132 tests** (108 host + 24 container).

The host tests run with `-W error::DeprecationWarning` (no deprecation
warnings since Priority 10). The container tests require the API
container (Docker-internal DNS `db:5432`, `vault:8200`).
## 3. Current Architecture

```text
Client HTTP
    │
    ▼
FastAPI / Uvicorn
    │
    ├──(1) JWT authentication (HS256, PyJWT, secret in Vault KV)──────▶ Vault KV-v2
    │                                                                (HS256 secret)
    │
    ├──(2) request signature─────────────────────────────────────────▶ HashiCorp Vault
    │                                                                (Ed25519 key)
    │
    ├──(3) send payload + signature─────────────────────────────────▶ PostgreSQL 16
    │                                                                (pgsodium + public key)
    │                                                                (RLS + RBAC)
    ▼
Docker volume securebiz_pgdata
Ports published on 127.0.0.1 only (no external exposure).

4. Quick Start

From the repository root, in PowerShell:

powershell
# Build and start all services (API, DB, Vault)
docker compose up --build -d

# Check container status
docker compose ps

# Verify API endpoints
Invoke-RestMethod http://localhost:8000/
Invoke-RestMethod http://localhost:8000/health

Expected output for /health:

text
status  api       database
------  ---       --------
healthy available connected

Stop the services without deleting data:

powershell
docker compose down

Do not use docker compose down -v unless you explicitly intend to destroy the PostgreSQL data volume.

4.1 Authentication Quick Test

The following test requires a provisioned user. A test user is available in the current environment:

powershell
# Login (test user only; password is documented in the handover)
$body = @{
    email    = "test-user@test.com"
    password = "TestPassword!2026"
} | ConvertTo-Json

$login = Invoke-RestMethod -Method Post `
    -Uri http://localhost:8000/auth/login `
    -ContentType "application/json" `
    -Body $body

$login.access_token

The refresh token is set as an HttpOnly, Secure, SameSite=Strict cookie on /auth.

5. Repository Structure

text
SecureBiz-Lab/
├── app/
│   ├── api/
│   │   ├── dependencies.py         # Tenant context (debug + JWT)
│   │   └── routes/
│   │       ├── auth.py             # /auth/login, /auth/refresh, /auth/logout
│   │       ├── organizations.py
│   │       ├── roles.py
│   │       └── users.py
│   ├── core/
│   │   ├── config.py               # Pydantic settings (fail-fast)
│   │   ├── database.py             # Psycopg connection manager (app + auth)
│   │   ├── jwt.py                  # JWT issuance + verification (HS256)
│   │   └── vault.py                # Vault Transit + Vault KV (JWT secret)
│   ├── models/
│   ├── schemas/
│   │   └── auth.py                 # LoginRequest, TokenResponse
│   ├── services/
│   │   ├── context_signing.py
│   │   └── refresh.py              # Refresh token rotation + revocation
│   └── main.py                     # FastAPI entry point
├── database/
│   ├── init/
│   │   └── 001-extension.sql
│   └── migrations/
│       ├── 001_iam_multitenant_v8.sql
│       └── 002_auth_session.sql
├── postgres/
│   └── Dockerfile                  # pgsodium compilation
├── docs/
│   ├── 01-presentation/
│   ├── 02-architecture/
│   ├── 03-installation/
│   ├── 04-developpement/
│   ├── 05-securite/
│   ├── 06-tests/
│   ├── 07-rapports/
│   └── glossary.md
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── CHANGELOG.md
├── ROADMAP.md
└── .env (not committed)

6. Documentation

- Overview
- Architecture
- Installation
- Development Guide
- Security & Threat Model
- Verifications & Tests
- Glossary
- Changelog
- Roadmap

7. Working Principles

- Never document a feature as operational before testing it.
- Never commit .env, passwords, tokens, or private keys.
- Perform migrations with a distinct account from the application account.
- Grant the application only the necessary privileges.
- Test security controls with the role actually used by the application.
- Keep validation evidence: commands, results (stripped of secrets), and reproducible tests.

8. Known Limitations

- Vault in -dev mode: acceptable for the lab, not for production.
- Vault root token (`dev-only-root-token`) is too powerful for production. A restricted policy (read on `transit/sign/securebiz-context`, `secret/data/securebiz/jwt`, `transit/keys/securebiz-context`) is required.
- `init_vault_key()` mixes Vault provisioning (mount engine, create key) with runtime. Must be separated in production.
- `@app.on_event("startup")` is deprecated in FastAPI 0.109+. Migration to `lifespan=` is pending.
- No automated key rotation: the JWT secret supports `current`/`previous` kids in Vault KV, but no rotation procedure exists yet.
- IAM routes (`/users`, `/organizations/me`, `/roles`) still use debug headers. JWT migration is Priority 6.
- `tests/test_isolation.py` still uses debug headers. Migration to JWT is Priority 6.
- No provisioning endpoint for new users with Argon2id hashes. Only one test credential exists.
- `auth_private.authenticate()` does not verify passwords itself; Argon2id verification is done in FastAPI (`app/api/routes/auth.py`).
- `pgsodium_trg_mask_update` event trigger disabled: only Ed25519 verification is used, not column masking.
- `securebiz_get_context()` is VOLATILE, not STABLE, which prevents plan-level caching in RLS policy evaluation.

9. Testing

Historical results (v0.3.0):

- `pytest`: 3/3 passed
- Bandit 1.9.4: 0 findings
- pip-audit 2.10.1: no known vulnerabilities at the time
- `scripts/state_check.py`: 4 OK, 6 skipped

Added in v0.4.0 (Priority 5):

- JWT unit tests (Bloc C): 18/18 passed
- Authentication functional tests (Bloc E2 v7): 8/8 passed (login, rotation, replay, logout)
- Disabled user test (Bloc E2 bis v4): 1/1 passed
- Total Priority 5: 9/9 passed
- Database state verified after tests: `credentials=1`, `refresh_tokens=0`, `active_tokens=0`, `user=active`

10. Maturity Warning

SecureBiz Lab is a prototype/laboratory under construction. It must not be presented as a production-ready security platform. Authentication is implemented and tested for the `/auth/*` endpoints, but:
- IAM routes still use debug headers (migration pending),
- no provisioning workflow exists,
- no CI/CD pipeline exists,
- Vault runs in development mode.

The cryptographic core (Vault → Ed25519 → PostgreSQL verification → RLS context) and the authentication layer (JWT → refresh tokens → rotation → reuse detection) have been validated and are documented in `docs/02-architecture/architecture.md`.
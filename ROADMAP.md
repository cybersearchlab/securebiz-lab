# SecureBiz Lab Roadmap

This roadmap describes planned objectives. It does **not** mean the listed
items are already implemented. A task is only marked as completed after
implementation, reproducible testing, and documentation updates.

## Phase 1 — Technical Foundation

-   [x] Initial FastAPI API.
-   [x] PostgreSQL in Docker Compose.
-   [x] API ↔ DB connection verified.
-   [x] Health check route (`GET /health`).
-   [x] Centralized configuration (`pydantic-settings`, fail-fast).
-   [x] Creation of `securebiz_app`, `securebiz_owner`, `securebiz_auth` roles.
-   [x] Grant and verify minimum privileges for the application role.
-   [x] Configure the API to use the limited application role (`securebiz_app`).

## Phase 2 — IAM Foundation

-   [x] Review and correction of the IAM migration (`001_iam_multitenant_v8.sql`).
-   [x] Definition of owner role (`securebiz_owner`, NOLOGIN) and migration role (`securebiz_user`, SUPERUSER).
-   [x] Migration tracking strategy (currently: manual SQL file naming).
-   [x] Creation of tables: organizations, users, memberships, roles, permissions, membership_roles, role_permissions.
-   [x] Constraints and indexes (unique slugs, case-insensitive email, composite FKs).
-   [x] Cross-organization consistency tests (partial: anti-replay, status checks).
-   [ ] Formal migration tracking tool (e.g., `sqitch`, `flyway`, or `alembic`).

## Phase 3 — Authentication and Authorization

-   [x] Credential storage strategy (`auth_private.credentials`, isolated schema).
-   [x] Function `auth_private.authenticate(email)` defined.
-   [x] Authentication database foundation: `auth_session` schema, `refresh_tokens` table, `get_user_status` function (migration `002_auth_session.sql`).
-   [x] Separate authentication database role (`securebiz_auth`) and connection (`get_auth_connection()`).
-   [x] JWT HS256 secret provisioned in Vault KV-v2 (`secret/data/securebiz/jwt`).
-   [x] JWT issuance (`create_access_token`) and verification (`verify_access_token`) with rotation support (`current_kid` / `previous_kid`).
-   [x] Argon2id password verification in FastAPI (`argon2-cffi==25.1.0`).
-   [x] Refresh token generation, storage (SHA-256 hash), rotation, reuse detection, family revocation.
-   [x] `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout` implemented and tested.
-   [x] `get_current_user()` dependency (Bearer JWT → `UserContext`).
-   [x] `get_authenticated_tenant_context()` dependency (JWT + `X-Organization-Id` → signed tenant context).
-   [x] Authentication functional tests: 9/9 passed (login, rotation, replay, logout, disabled user).
-   [ ] Registration / invitation / account activation flow.
-   [x] Provisioning endpoint or script for Argon2id password hashes.
-   [x] Migration of IAM routes (`/users`, `/organizations/me`, `/roles`) to `get_authenticated_tenant_context()`.
-   [x] Removal or deprecation of `X-Debug-*` headers from the production code path. (P10: get_tenant_context removed, no route imports X-Debug-*.)
-   [x] Role assignment and permission checks enforced at the route level (RBAC middleware).
-   [ ] Negative tests and suspended-account handling in the automated test suite.

## Phase 4 — Multi-Tenant Isolation

-   [x] Define the tenant context lifecycle (`transaction_context`, `xid8`, `set_config` avoided).
-   [x] Enable and force RLS on tenant-scoped tables.
-   [x] Write testable policies for each operation (SELECT/INSERT/UPDATE/DELETE).
-   [x] Test with a non-privileged role (`securebiz_app`).
-   [x] Document the threat model and its limitations (`docs/05-securite/security.md`).
-   [x] Automated isolation tests between two organizations (Pytest).
-   [x] Test cross-organization access attempts (F2 covers /organizations/me; /users and /roles pending).
-   [x] Tenant isolation tests under JWT authentication (after IAM route migration).

## Phase 5 — Cryptography and Security

-   [x] HashiCorp Vault Transit integration (Ed25519, non-exportable private key).
-   [x] `pgsodium 3.1.9` compiled in custom PostgreSQL image.
-   [x] `securebiz_install_context()` verifies Ed25519 signature with `pgsodium`.
-   [x] `securebiz_get_context()` returns identity bound to `pg_current_xact_id()`.
-   [x] Anti-replay protection via `used_jti` and atomic `INSERT ... ON CONFLICT`.
-   [x] Claim validation (`iss`, `aud`, `sub`, `org`, `iat`, `exp`, `jti`, max 60s lifetime).
-   [x] Public key registration (`securebiz_register_public_key`) and revocation.
-   [x] **End-to-end cryptographic flow validated** (documented in `CHANGELOG.md` and `docs/02-architecture/architecture.md`).
-   [x] JWT HS256 secret in Vault KV-v2 (not in `.env`, not in source code).
-   [x] Argon2id password hashing parameters documented and applied consistently.
-   [ ] Automated key rotation procedure (JWT `current`/`previous` kids and Ed25519 `kid`).
-   [ ] Vault production configuration (mTLS, audit, seal/unseal).
-   [ ] Restricted Vault token policy for the API (read-only on `transit/sign/securebiz-context`, `transit/keys/securebiz-context`, `secret/data/securebiz/jwt`).
-   [ ] Separation of Vault provisioning (mount engine, create key) from runtime operations.

## Phase 6 — Security and Quality

-   [x] Unit, API, and integration tests (extend `tests/` with JWT, refresh, isolation).
-   [x] Extend `scripts/state_check.py` to cover `auth_session.refresh_tokens`, `get_user_status`, `auth_private.credentials`.
-   [ ] Dependency audit (`pip-audit`).
-   [ ] Static analysis (`bandit`) and formatting (`black`, `ruff`).
-   [ ] Centralized secrets management (Vault as the only secret store, no `.env` secrets).
-   [ ] Logging and audit of sensitive events (login success/failure, token rotation, revocation, replay detection).
-   [ ] Container and image hardening (`trivy`, minimal base images).
-   [x] FastAPI `@app.on_event("startup")` migration to `lifespan=`. (P10: pp/main.py now uses @asynccontextmanager async def lifespan(app).)

## Phase 7 — DevSecOps and Demonstration

-   [ ] CI pipeline (GitHub Actions).
-   [ ] Automated tests on every change.
-   [ ] Security checks in the pipeline (SAST, DAST, dependency scanning).
-   [ ] Operations documentation.
-   [ ] Reproducible demonstration scenarios.
-   [ ] Final security report of the lab.

## Task Closure Rule

A task is only marked as completed after implementation, reproducible
testing, and documentation update. Checkboxes must only be ticked after
verification. Evidence must be preserved in `docs/06-tests/`.
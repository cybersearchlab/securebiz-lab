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
-   [x] Function `auth_private.authenticate(email)` defined (not yet wired into FastAPI).
-   [ ] Registration / invitation / account activation flow.
-   [ ] Authentication and session/token management (JWT).
-   [ ] Argon2 password hashing and verification.
-   [ ] Active membership verification at login.
-   [ ] Role assignment and permission checks in FastAPI middleware.
-   [ ] Negative tests and suspended-account handling.

## Phase 4 — Multi-Tenant Isolation

-   [x] Define the tenant context lifecycle (`transaction_context`, `xid8`, `set_config` avoided).
-   [x] Enable and force RLS on tenant-scoped tables.
-   [x] Write testable policies for each operation (SELECT/INSERT/UPDATE/DELETE).
-   [x] Test with a non-privileged role (`securebiz_app`).
-   [x] Document the threat model and its limitations (`docs/05-securite/security.md`).
-   [ ] Automated isolation tests between two organizations (Pytest).
-   [ ] Test cross-organization access attempts (partially done manually).

## Phase 5 — Cryptography and Security (new)

-   [x] HashiCorp Vault Transit integration (Ed25519, non-exportable private key).
-   [x] `pgsodium 3.1.9` compiled in custom PostgreSQL image.
-   [x] `securebiz_install_context()` verifies Ed25519 signature with `pgsodium`.
-   [x] `securebiz_get_context()` returns identity bound to `pg_current_xact_id()`.
-   [x] Anti-replay protection via `used_jti` and atomic `INSERT ... ON CONFLICT`.
-   [x] Claim validation (`iss`, `aud`, `sub`, `org`, `iat`, `exp`, `jti`, max 60s lifetime).
-   [x] Public key registration (`securebiz_register_public_key`) and revocation.
-   [x] **End-to-end cryptographic flow validated** (documented in `CHANGELOG.md` and `docs/02-architecture/architecture.md`).
-   [ ] Automated key rotation procedure.
-   [ ] Vault production configuration (mTLS, audit, seal/unseal).

## Phase 6 — Security and Quality

-   [ ] Unit, API, and integration tests.
-   [ ] Dependency audit (`pip-audit`).
-   [ ] Static analysis (`bandit`) and formatting (`black`, `ruff`).
-   [ ] Centralized secrets management.
-   [ ] Logging and audit of sensitive events.
-   [ ] Container and image hardening (`trivy`, minimal base images).

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


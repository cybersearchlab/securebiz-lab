# SecureBiz Lab Overview

## Objective

SecureBiz Lab is a technical laboratory dedicated to business application
security and DevSecOps practices. It is designed to build, test, and
document security controls within a web/API application connected to a
PostgreSQL database.

## Study Areas

-   **REST API Security**: Input validation, authentication, authorization,
    error handling, and abuse prevention (rate limiting).
-   **IAM**: Identities, organizations, memberships, roles, and permissions.
-   **Data Security**: PostgreSQL privileges, separation of duties,
    migrations, and auditing.
-   **Multi-tenancy**: Data isolation between organizations.
-   **Cryptography**: Ed25519 asymmetric signatures, Vault Transit,
    PostgreSQL `pgsodium` verification, and HS256 JWT with a secret stored
    in Vault KV-v2.
-   **Authentication**: Argon2id password verification, opaque refresh
    tokens with rotation and reuse detection.
-   **Infrastructure Security**: Containers, configuration, secrets management,
    and network isolation.
-   **DevSecOps**: Automated testing and security checks integrated into
    the development lifecycle.

## Audience and Usage

This repository serves as a demonstration, learning, and skill-showcase
platform. It can be used to illustrate a methodology for assessing and
hardening the security of business applications. It does not constitute
proof that a third-party system has been audited, nor does it claim that
a vulnerability exists in any specific company.

## Current Scope

The currently verified foundation includes:

- **API**: FastAPI application with strict configuration validation
  (`pydantic-settings`, fail-fast on missing variables).
- **Database**: PostgreSQL 16 running in a custom Docker image
  (with `pgsodium 3.1.9` compiled in).
- **Cryptography (tenant context)**: HashiCorp Vault 1.20 (Transit engine)
  with a non-exportable Ed25519 private key. The private key **never leaves Vault**.
- **Cryptography (JWT)**: HS256 access tokens (PyJWT 2.10.1), secret stored
  in Vault KV-v2 at `secret/data/securebiz/jwt`. The secret is never written
  to `.env`, source code, or logs.
- **Authentication**: Argon2id password verification (`argon2-cffi 25.1.0`),
  JWT issuance and verification, opaque refresh tokens with SHA-256 storage,
  rotation on every use, reuse detection with family revocation, HttpOnly
  Secure SameSite=Strict cookie.
- **IAM Schema**: 7 business tables + 3 private schemas (`auth_private`,
  `auth_security`, `auth_session`) applied via `001_iam_multitenant_v8.sql`
  and `002_auth_session.sql`.
- **Multi-tenant Isolation**: `FORCE ROW LEVEL SECURITY` on all
  tenant-scoped tables, with RBAC enforced in SQL (`app_has_permission()`).
  JWT-based route-level RBAC is planned (Priority 6).
- **Orchestration**: Docker Compose (3 services: `api`, `db`, `vault`).

### Validated end-to-end

The cryptographic chain has been **proven by a real test** executed with
`securebiz_app`:

1.  Vault signs a JSON payload (claims: `iss`, `aud`, `sub`, `org`, `iat`,
    `exp`, `jti`) with its Ed25519 private key.
2.  PostgreSQL verifies the 64-byte signature with `pgsodium`.
3.  `securebiz_install_context()` validates claims and installs the context
    bound to `pg_current_xact_id()`.
4.  `securebiz_get_context()` returns the correct `user_id` and
    `organization_id`.
5.  Transaction is rolled back (test data not persisted).

This is documented in `CHANGELOG.md` (v0.3.0) and
`docs/02-architecture/architecture.md` §4.

### Validated authentication (v0.4.0)

The authentication chain has been **proven by 9/9 functional tests**:

1.  `POST /auth/login` verifies email + password (Argon2id), checks user status,
    issues an HS256 JWT and a refresh cookie (HttpOnly, Secure, SameSite=Strict,
    Path=/auth, Max-Age=604800).
2.  `POST /auth/refresh` rotates the refresh token (new cookie, same family_id),
    re-checks the user status, and issues a new JWT. A disabled user's family
    is revoked and the request returns 401.
3.  Replaying a revoked refresh token returns 401 and revokes the entire family.
4.  `POST /auth/logout` revokes the family and clears the cookie (idempotent).
5.  All tests verified in DB: `credentials=1`, `refresh_tokens=0`,
    `active_tokens=0`, `user=active`.

This is documented in `CHANGELOG.md` (v0.4.0) and
`docs/06-tests/verifications.md` §6–§13.

### Not yet delivered

- FastAPI IAM routes migrated to JWT (`/organizations`, `/users`, `/roles`
  still use debug headers — Priority 6).
- Route-level RBAC middleware (JWT permission checks at the route level).
- Provisioning endpoint or script for Argon2id password hashes.
- Automated multi-tenant isolation tests under JWT (Pytest).
- Automated Ed25519 and JWT secret rotation.
- `scripts/state_check.py` extension for `auth_session.refresh_tokens`,
  `get_user_status`, `auth_private.credentials`.
- CI/CD pipeline with DevSecOps checks.

## Documentation Rule

Each description must carry one of the following statuses when applicable:

-   **In place and verified**: Tested in the project environment.
-   **In progress**: Development started, validation incomplete.
-   **Planned**: Design objective not yet realized.

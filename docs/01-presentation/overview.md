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
-   **Cryptography**: Ed25519 asymmetric signatures, Vault Transit, and
    PostgreSQL `pgsodium` verification.
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
- **Cryptography**: HashiCorp Vault 1.20 (Transit engine) with a
  non-exportable Ed25519 private key. The private key **never leaves Vault**.
- **IAM Schema**: 7 business tables + 2 private schemas (`auth_private`,
  `auth_security`) applied via `001_iam_multitenant_v8.sql`.
- **Multi-tenant Isolation**: `FORCE ROW LEVEL SECURITY` on all
  tenant-scoped tables, with RBAC enforced both in FastAPI (future) and
  in SQL (`app_has_permission()`).
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
`docs/02-architecture/architecture.md`.

### Not yet delivered

- FastAPI business routes (`/organizations`, `/users`, `/roles`).
- Authentication flow (login, Argon2 hashing, JWT emission).
- Automated multi-tenant isolation tests (Pytest).
- Automated Ed25519 key rotation.
- CI/CD pipeline with DevSecOps checks.

## Documentation Rule

Each description must carry one of the following statuses when applicable:

-   **In place and verified**: Tested in the project environment.
-   **In progress**: Development started, validation incomplete.
-   **Planned**: Design objective not yet realized.
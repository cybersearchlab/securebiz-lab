# SecureBiz Lab

**Security Assessment & DevSecOps for Business Applications**

> Document status: v0.3.0 — November 10, 2026
> Project status: Technical prototype — cryptographic architecture validated

## 1. Overview

SecureBiz Lab is a laboratory project designed to demonstrate a structured approach to securing business applications. It serves as a practical sandbox to explore API security, Identity and Access Management (IAM), database security, multi-organization isolation, and DevSecOps practices.

The project is developed incrementally. The documentation systematically distinguishes between **verified features**, **ongoing work**, and **future objectives**.

## 2. Current Verified State

### 2.1 Infrastructure

- **API**: Python 3.12, FastAPI, Uvicorn.
- **Database**: PostgreSQL 16 (Bookworm) with `pgsodium 3.1.9` compiled in a custom image.
- **Cryptography**: HashiCorp Vault 1.20 (Transit engine) with a **non-exportable Ed25519 key**.
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
- **RBAC** enforced both in FastAPI (future) and in SQL (`app_has_permission()`).

### 2.4 PostgreSQL roles

| Role | Attributes | Purpose |
| :--- | :--- | :--- |
| `securebiz_user` | SUPERUSER, LOGIN | Migration admin. Not used by the API. |
| `securebiz_owner` | NOLOGIN, NOBYPASSRLS | Owns security functions (`SECURITY DEFINER`). |
| `securebiz_app` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Business API. |
| `securebiz_auth` | LOGIN, NOSUPERUSER, NOBYPASSRLS | Authentication only. |

## 3. Current Architecture

```text
Client HTTP
    │
    ▼
FastAPI / Uvicorn  ──(1) request signature──▶  HashiCorp Vault
    │                                          (Ed25519 private key)
    │
    ├──(2) send payload + signature──▶  PostgreSQL 16
    │                                   (pgsodium + public key)
    │                                   (RLS + RBAC)
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

5. Repository Structure
text
SecureBiz-Lab/
├── app/
│   ├── api/
│   ├── core/
│   │   ├── config.py       # Pydantic settings (fail-fast)
│   │   ├── database.py     # Psycopg connection manager
│   │   └── vault.py        # Vault Transit initialization
│   ├── models/
│   ├── schemas/
│   ├── services/
│   └── main.py             # FastAPI entry point
├── database/
│   ├── init/
│   │   └── 001-extension.sql
│   └── migrations/
│       └── 001_iam_multitenant_v8.sql
├── postgres/
│   └── Dockerfile          # pgsodium compilation
├── docs/
│   ├── 01-presentation/
│   ├── 02-architecture/
│   ├── 03-installation/
│   ├── 04-developpement/
│   ├── 05-securite/
│   ├── 06-tests/
│   └── glossary.md
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── CHANGELOG.md
└── .env (not committed)
6. Documentation
Overview

Architecture

Installation

Development Guide

Security & Threat Model

Verifications & Tests

Glossary

Changelog

7. Working Principles
Never document a feature as operational before testing it.

Never commit .env, passwords, tokens, or private keys.

Perform migrations with a distinct account from the application account.

Grant the application only the necessary privileges.

Test security controls with the role actually used by the application.

Keep validation evidence: commands, results (stripped of secrets), and reproducible tests.

8. Known Limitations
Vault in -dev mode: acceptable for the lab, not for production.

No automated key rotation: the design supports multiple keys via kid, but no rotation procedure exists yet.

auth_private.authenticate() not yet wired into FastAPI: the login flow is defined but not implemented.

No automated isolation tests yet: Pytest suite for multi-tenant isolation is planned.

pgsodium_trg_mask_update event trigger disabled: only Ed25519 verification is used, not column masking.

9. Maturity Warning
SecureBiz Lab is a prototype/laboratory under construction. It must not be presented as a production-ready security platform. Authentication, authorization routes, automated testing, and CI/CD pipelines remain to be implemented and validated.

The cryptographic core (Vault → Ed25519 → PostgreSQL verification → RLS context) has been validated and is documented in docs/02-architecture/architecture.md.
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
| Minimal privileges for `securebiz_app` | **Granted** (migration V8) |
| Multi-tenant RLS Isolation | **Enabled and forced** on all tenant-scoped tables |
| RBAC in SQL | **In place** (`app_has_permission()`) |
| Anti-replay (`used_jti`) | **In place** (atomic `INSERT ... ON CONFLICT`) |
| Claim validation (`iss`, `aud`, `exp`, `jti`) | **In place** (max 60s lifetime) |
| API Authentication (login) | Planned |
| Permission-based Authorization (FastAPI middleware) | Planned |
| Secure Password Hashing (Argon2) | Planned (`auth_private.credentials` defined) |
| Audit Log | Planned |
| Automated Security Tests | Planned (Pytest) |
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

## Risks and Mitigations

### Secrets

The `.env` file must be ignored by Git and protected on the development
machine. An `.env.example` file without secret values can document the
required variables. **Vault holds the Ed25519 private key; it is never
stored in `.env` or in PostgreSQL.**

### PostgreSQL Application Account

The initialization superuser account (`securebiz_user`) must not be used
by the API. The `securebiz_app` role has the required privileges (granted
via migration V8) and is used by the API. Its attributes have been audited:
`NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`.

The `securebiz_owner` role is NOLOGIN and has no `BYPASSRLS`. It is used
only via `SECURITY DEFINER` functions. The `securebiz_auth` role is
dedicated to authentication and cannot read the business tables directly.

### Password Hashes

Password hashes are stored in `auth_private.credentials`, a schema that
is **not accessible to `securebiz_app`**. Only the `auth_private.authenticate(email)`
function (owned by `securebiz_owner`, `SECURITY DEFINER`) can read them.
This function is granted only to `securebiz_auth`.

Password hashes must never be included in API responses. The future login
flow will use Argon2 for hashing and verification.

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

## Known Limitations

-   **Vault in `-dev` mode**: acceptable for the lab, not for production.
-   **No automated key rotation**: the design supports multiple keys via `kid`, but no rotation procedure exists yet.
-   **`auth_private.authenticate()` not yet wired into FastAPI**: the login flow is defined but not implemented.
-   **No automated isolation tests yet**: Pytest suite is planned.
-   **`pgsodium_trg_mask_update` event trigger disabled**: only Ed25519 verification is used, not column masking.
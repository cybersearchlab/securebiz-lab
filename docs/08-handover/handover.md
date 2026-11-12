Handover v13 — Message 1 sur 3 : §1 à §14
Voici le contenu à coller dans ton fichier MASTER HANDOVER PROMPT — SECUREBIZ LAB v13.txt. Aucun #, aucun " dans le texte lui-même — style du v12.

text
MASTER HANDOVER PROMPT — SECUREBIZ LAB
Version 13 — Priority 5 Complete (Authentication and Session Management), 
Rebuild Image Pending, and Readiness for Priority 6 (Route Migration)
Snapshot date: 12 November 2026
Project directory: C:\Users\nguey\Documents\SecureBiz-Lab
Environment: Windows 11, PowerShell (5.1), Docker Desktop with WSL2, Python 3.12 in the API container, PostgreSQL 16, FastAPI, psycopg, HashiCorp Vault 1.20 (dev mode), pgsodium 3.1.9.

1. PURPOSE AND OPERATING INSTRUCTIONS
You are taking over an ongoing technical and security engineering project named SecureBiz Lab.

This document is the consolidated Version 13 handover. It supersedes Version 12.

It incorporates:

The complete Priority 5 implementation (JWT authentication, refresh tokens, authentication routes, authenticated dependencies).
All 9 functional tests passed on 12 November 2026 (P1-P8 and P11).
The 8 operational and technical corrections discovered during Priority 5.
The current state: Priority 5 is CLOSED, the rebuild of the API image is PENDING (critical technical debt).
The exact continuation point: Priority 6 (migration of IAM routes to JWT) or Priority 7 (rebuild).

Do not restart the project from Version 12. Do not repeat completed inspections. Do not treat a proposed architecture as implemented merely because it has been discussed.

The purpose is to continue from the actual state of the project, not from an earlier proposed inspection plan.

1.1 Rules for distinguishing evidence
Use the following categories throughout the investigation:

Verified: directly supported by an observed source file or command output.
Historical: reported by an earlier inspection, but the complete original output is not available in the current handover.
Inferred: a technical interpretation of verified facts.
Open: not yet established.
Proposed: a recommendation that has not been implemented or approved.

Never present an inference or historical finding as a newly verified fact.

1.2 Communication and execution rules
The user communicates in French.
Explain technical reasoning and instructions in French.
Write source code, SQL comments, API documentation, technical specifications and project documentation in English unless explicitly requested otherwise.
Work incrementally: one operation at a time.
Inspect files before modifying them.
Do not modify several files at once unless explicitly requested and justified.
Provide complete PowerShell commands that can be copied and executed directly.
Explain the purpose of each command and its expected output.
Wait for the user's actual output before deciding the next operation.
Never invent command results, file contents, database states, security guarantees or test results.
Do not ask questions whose answers are already documented here.
Prefer read-only inspection before modifications.
Before proposing a database change, inspect the relevant live schema, privileges, policies, functions and dependencies.
Do not treat a proposed architecture as implemented merely because it has been discussed.
After each completed inspection, update the project state and identify the next operation explicitly.
Preserve the exact investigation history and avoid repeating completed work.
When a command is intended for PowerShell, provide the complete block in one piece.

1.3 Absolute security restrictions
Never request or display:

.env file contents (values);
database passwords;
Vault tokens;
private keys;
JWT signing secrets;
password hashes;
other credentials or secrets.

Never execute destructive commands such as:

powershell
docker compose down -v

Never delete, recreate, reset or replace the PostgreSQL data volume.

Never:

disable RLS;
remove FORCE ROW LEVEL SECURITY;
grant superuser privileges to runtime accounts;
grant BYPASSRLS to runtime roles;
weaken tenant isolation to make a test pass;
reset the database to solve an authentication problem;
modify unrelated Docker containers;
use the migration/admin role as a runtime application account.

Unrelated containers that must remain untouched:

kboutscan-dev-postgres — port 5432;
kboutscan-dev-redis — port 6379.

SecureBiz PostgreSQL uses host port 5433, mapped to container port 5432.

1.4 New operational pitfalls introduced in v13
In addition to the v12 pitfalls (Add-Content without trailing newline, [Convert]::ToHexString absence, Set-Clipboard failure, VAULT_DEV_ROOT_TOKEN static), Version 13 introduces the following corrections, all verified on 12 November 2026:

1.4.1 httpx.ASGITransport does NOT inject cookies set via cookies.set()
When using httpx.AsyncClient or httpx2.AsyncClient with ASGITransport(app=app), cookies added via client.cookies.set(...) are stored in the jar but NOT sent in the Cookie header of subsequent requests.
Verified: client.cookies.clear() then client.cookies.set("refresh_token", token, domain="testserver", path="/auth") then client.post("/auth/refresh") sends no cookie. The server returns 401 with detail "Refresh token required." (cookie absent), not "Invalid refresh token." (cookie present but invalid).
Corrective: send the cookie via an explicit header: client.post("/auth/refresh", headers={"Cookie": f"refresh_token={token}"}). This works for both httpx and httpx2.
This is a known limitation of the ASGI transport in both packages. TestClient of Starlette 1.10.0 inherits it.

1.4.2 TestClient requires httpx2
fastapi.testclient.TestClient imports starlette.testclient which raises RuntimeError if httpx2 is not installed. httpx2 is a separate package from httpx (version 2.16.0, with httpcore2 and truststore). Installing httpx2 via pip install httpx2 was needed.
Both httpx and httpx2 have the cookie limitation described in 1.4.1. Using httpx.AsyncClient directly with explicit Cookie header avoids the dependency on httpx2 for tests. httpx2 remains needed only if TestClient is used.

1.4.3 $LASTEXITCODE is unreliable for docker exec psql and docker cp
PowerShell sets $LASTEXITCODE to 1 when a native command writes to stderr, even if the command succeeded. psql writes banners and warnings to stderr. docker cp writes "Successfully copied" to stderr. docker exec relays stderr.
Corrective: do not check $LASTEXITCODE after psql UPDATE or docker cp. Instead, verify the actual database state with a SELECT, or verify the file exists with Test-Path.

1.4.4 $ErrorActionPreference = "Stop" stops the script on native stderr
If $ErrorActionPreference is Stop (as observed in this session), any docker exec or docker cp writing to stderr raises a terminating error that stops the PowerShell script.
Corrective: wrap the orchestration block in try/finally and set $ErrorActionPreference = "Continue" locally. Restore the previous value in the finally block.
Example:
savedEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    ... operations ...
} finally {
    $ErrorActionPreference = $savedEAP
}

1.4.5 psql -t -A with RETURNING returns two lines
psql -t -A -c "INSERT ... RETURNING user_id" returns two lines: the UUID and INSERT 0 1. A strict -ne comparison against the UUID fails.
Corrective: parse with a regex (-match '^[0-9a-f-]{36}$') or split on newline and take the first line.

1.4.6 users_status_check allows only active, disabled, pending
Verified 12 November 2026:
CHECK (status IN ('active', 'disabled', 'pending'))
'inactive' is REJECTED. To disable a user, use 'disabled'.

1.4.7 Fragment execution of an Invoke-Block function causes silent failure
Running function Invoke-BlockX { ... } fragments (for example copying only the docker cp line, or only the throw line) causes:

variables to be undefined in global scope;
throw to execute without the finally block (no reactivation, no cleanup);
silent state corruption.

Rule: always execute function Invoke-BlockX { ... } Invoke-BlockX as a single atomic block. Use clipboard paste-all then Enter.

1.4.8 docker compose build api is safe but can time out on PyPI
docker compose build api only builds an image. It does not modify docker-compose.yml, Dockerfile, requirements.txt, .env, containers, or volumes. It reads requirements.txt and runs pip install inside the Docker build.
PyPI timeouts (ReadTimeoutError on files.pythonhosted.org) are transitory on WSL2. Retry usually succeeds.

2. PROJECT OBJECTIVE AND TARGET SECURITY ARCHITECTURE
SecureBiz Lab is a multi-tenant cybersecurity and business security platform.

The current technical work focuses on:

user identity;
organizations;
organization memberships;
role-based access control;
tenant isolation;
signed tenant context;
PostgreSQL Row-Level Security;
Vault Transit-based context signing;
authenticated API access;
authentication sessions with JWT and refresh tokens.

The target security chain is:

text
Client
  |
  v
FastAPI application
  |
  v
JWT authentication (HS256, PyJWT, secret in Vault KV)
  |
  v
Authenticated user identity
  |
  v
User-status validation
  |
  v
Active organization membership verification
  |
  v
RBAC permission authorization
  |
  v
Vault Transit signed tenant context
  |
  v
PostgreSQL context verification
  |
  v
Row-Level Security
  |
  v
Tenant-scoped data

Security principles:

A client-supplied organization ID is not proof of membership.
A signed tenant context is not proof of user authentication.
Vault signing must not be confused with JWT validation.
Database membership verification must remain in place.
RLS must remain enabled and correctly enforced.
SECURITY DEFINER routines must be reviewed in their actual execution context.
A route docstring is not proof that authorization is enforced.
A UUID is an identifier, not an authentication credential.
JWT HS256 authenticates the user to the API. Vault Transit Ed25519 signs the tenant context for PostgreSQL. These two mechanisms must never be confused.
Refresh tokens are opaque, stored hashed (SHA-256), rotated on every use, and grouped into revocable families with reuse detection.

As of Version 13, the authentication portion of this chain is fully implemented and tested for the /auth/* endpoints. The IAM routes (users, organizations, roles) still use the debug-header path and will be migrated in Priority 6.

3. DEVELOPMENT ENVIRONMENT
3.1 Local environment
Operating system: Windows 11.
Shell: PowerShell (version 5.1, as confirmed by the [Convert]::ToHexString absence).
Docker Desktop with WSL2.
Host Python observed: Python 3.13.7.
API container Python observed: Python 3.12.16.
PostgreSQL 16.
psycopg 3.
FastAPI 0.162.2.
pgsodium 3.1.9.
HashiCorp Vault 1.20 in development mode.
Project path:

text
C:\Users\nguey\Documents\SecureBiz-Lab

Do not confuse host Python with API-container Python.

3.2 Docker services
Compose services:

api
db
vault

Container names:

securebiz-api
securebiz-postgres
securebiz-vault

Database mapping:

text
127.0.0.1:5433 -> container:5432

API-to-database connection:

text
DB_HOST=db
DB_PORT=5432

Persistent database volume:

text
securebiz_pgdata

Never delete or recreate this volume.

PostgreSQL initialization scripts are mounted from:

text
database/init

into:

text
/docker-entrypoint-initdb.d

Initialization scripts normally execute only when the PostgreSQL data directory is initialized for the first time. Editing an initialization script does not cause it to run automatically against the existing database.

3.3 Current Compose configuration
The complete docker-compose.yml was inspected on 11 November 2026.

The API database environment uses:

text
DB_HOST: db
DB_PORT: 5432
DB_NAME: ${POSTGRES_DB}
DB_USER: ${APP_DB_USER}
DB_PASSWORD: ${APP_DB_PASSWORD}
AUTH_DB_USER: securebiz_auth
AUTH_DB_PASSWORD: ${AUTH_DB_PASSWORD}

The API also receives:

text
VAULT_ADDR: http://vault:8200
VAULT_TOKEN: ${VAULT_DEV_ROOT_TOKEN}
APP_ENV: development
DEBUG_HEADERS: "true"

The Vault service uses development mode with -dev-root-token-id=dev-only-root-token. The root token is static and does not change on container recreation.

The API currently has two explicitly configured database accounts:

business role: securebiz_app;
authentication role: securebiz_auth.

3.4 PostgreSQL Dockerfile
The complete postgres/Dockerfile was inspected.

It uses:

dockerfile
FROM postgres:16-bookworm

and builds pgsodium 3.1.9 from PGXN.

It does not create application users, configure database passwords or implement provisioning.

The presence of pgsodium does not prove Argon2id is installed or that password hashing is implemented in PostgreSQL.

3.5 Image build state — new in v13
The securebiz-lab-api:latest image (hash 4d743ef9b544, 292MB) is the v12 image.

The Priority 5 packages (PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1, httpx2 2.16.0) were installed manually via pip install in the running container and are NOT persisted in the image.

This is a critical technical debt: if the securebiz-api container restarts (crash, docker compose restart, Windows reboot), the packages disappear and the API crashes at startup with ModuleNotFoundError.

A first attempt to rebuild (docker compose build api) failed on 12 November 2026 with ReadTimeoutError on files.pythonhosted.org. The network was subsequently verified as reachable (python:3.12-slim pull succeeded, PyPI reachable). A retry is pending.

The required fix before Priority 6 is: docker compose build api then docker compose up -d --force-recreate api, followed by a verification of Total paths: 8 and the package versions.

4. REPOSITORY INVENTORY
The latest recursive inventory excluded .git, .venv, caches and .env.

Observed structure (updated for v13):

text
app/
    api/
        dependencies.py          (modified in Priority 5)
        routes/
            organizations.py     (unchanged, still uses get_tenant_context)
            roles.py             (unchanged, still uses get_tenant_context)
            users.py             (unchanged, still uses get_tenant_context)
            auth.py              (new in Priority 5)
    core/
        config.py                (modified in Priority 5)
        database.py              (modified in v12)
        jwt.py                   (new in Priority 3)
        vault.py                 (modified in Priority 2)
    schemas/
        auth.py                  (new in Priority 5)
    services/
        context_signing.py       (unchanged)
        refresh.py               (rewritten in Priority 4)
    main.py                      (modified in Priority 5)

database/
    init/
        001-extension.sql
    migrations/
        001_iam_multitenant_v8.sql
        002_auth_session.sql

docs/
    01-presentation/
    02-architecture/
    03-installation/
    04-developpement/
    05-securite/
    06-tests/
    07-rapports/
    glossary.md

postgres/
    Dockerfile

scripts/
    state_check.py

tests/
    test_isolation.py

docker-compose.yml
Dockerfile
requirements.txt
README.md
CHANGELOG.md
ROADMAP.md

Correction versus earlier handovers: database/init/000-create-app-user.sql, described in v6/v7 as inspected and containing a password placeholder, does not exist in the current repository. The database/init/ directory contains only 001-extension.sql. Do not treat the earlier description of 000-create-app-user.sql as a verified artifact.

No obvious dedicated provisioning or seeding script was found in the inspected inventory.

Important files:

File	Responsibility
app/main.py	FastAPI initialization and startup
app/api/dependencies.py	Tenant-context dependencies (debug and JWT)
app/api/routes/users.py	User routes (still debug headers)
app/api/routes/organizations.py	Organization routes (still debug headers)
app/api/routes/roles.py	Role routes (still debug headers)
app/api/routes/auth.py	Authentication routes (new in Priority 5)
app/core/config.py	Configuration (DB, AUTH_DB, JWT settings)
app/core/database.py	PostgreSQL connections (business + auth)
app/core/jwt.py	JWT issuance and verification
app/core/vault.py	Vault integration + get_jwt_secret
app/schemas/auth.py	LoginRequest and TokenResponse
app/services/context_signing.py	Context signing
app/services/refresh.py	Refresh token storage, rotation, revocation
database/migrations/001_iam_multitenant_v8.sql	IAM, multi-tenancy, security functions and RLS
database/migrations/002_auth_session.sql	Auth session schema, refresh tokens, get_user_status
scripts/state_check.py	State checks
tests/test_isolation.py	Tenant-isolation tests (still debug headers)

4.1 Git history — verified 11 November 2026
git is available (2.56.0.windows.4). The repository root is C:/Users/nguey/Documents/SecureBiz-Lab, branch main, not a shallow clone, with one single commit:

text
2362024 (HEAD -> main, origin/main) feat: v0.3.0 - validated cryptographic architecture (Vault + pgsodium + RLS)

The working tree was clean at the last v12 inspection.

git log --all --oneline -S searches for INSERT INTO public.users, INSERT INTO public.memberships, and INSERT INTO auth_private.credentials returned zero matching commits. Because the repository is not shallow and contains exactly one commit, this proves that no such statement was ever committed.

Inference (not verified artifact): the existing active user, membership, and organization were provisioned by a manual, unversioned psql operation executed by securebiz_user during the 09-10 November 2026 session, using the test UUIDs now hardcoded in scripts/state_check.py (see Section 4.2). This remains unknown as a versioned artifact, but is defensible as manually provisioned with hardcoded test identities.

New in v13: the Priority 5 changes (9 files) have not been committed yet. A git add -A, git commit, and git push is recommended after the rebuild is validated.

4.2 Hardcoded test identities in scripts/state_check.py — verified 11 November 2026
scripts/state_check.py (11343 bytes) contains the following hardcoded values:

python
EXPECTED_PUBKEY_HEX = (
    "ccc071be49abbcdef22b541bb7ad984de"
    "1364730814dde3d54b9844a370a4e89"
)

TEST_USER_ID = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
TEST_ORG_ID  = "1a40e607-b991-4b06-ad1f-13106d65b12a"

These values identify the unique existing active user, the unique existing active organization, and the current Vault Ed25519 public key.

They are identifiers, not credentials. Their exposure is not an authentication bypass. They are nevertheless a maintenance and hygiene concern:

The test UUIDs are hardcoded rather than read from environment variables.
EXPECTED_PUBKEY_HEX is coupled to the Vault -dev mode, which regenerates the key on container recreation (setup.md:120, development.md:80). A Vault recreation invalidates this constant until it is manually updated.
These UUIDs must not be reused in production or in any future provisioning workflow.

Note: the Vault container has not been recreated in the current session, so the public key remains valid and EXPECTED_PUBKEY_HEX is still accurate.

Do not modify state_check.py during the current handover adoption. This is a documented finding, not a remediation task in this session.

4.3 scripts/state_check.py behavior — verified 11 November 2026
The script:

reads VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY from environment;
optionally reads DB_ADMIN_USER, DB_ADMIN_PASSWORD (if absent, structural checks are SKIP, not FAIL);
checks environment variables;
checks existence of the 11 expected tables in information_schema.tables (note: does not yet check auth_session.refresh_tokens);
checks existence of install_context, get_context, cleanup_context in auth_security;
checks that the public key row for securebiz-context exists, is not revoked, and matches EXPECTED_PUBKEY_HEX;
checks that the user/membership/organization triplet is (active, active, active);
performs an independent Vault Transit signature and verifies it returns a 64-byte Ed25519 signature;
executes an end-to-end install_context + get_context(user_id) + get_context(organization_id) test, then rolls back (conn.rollback() in finally), so no data is persisted;
prints a summary and exits with code 0 or 1.

The script does not call securebiz_register_public_key, securebiz_revoke_public_key, securebiz_purge_expired_security_data, or get_user_status.

The script does duplicate a portion of the Vault signing logic already present in app/services/context_signing.py, intentionally, for cross-validation. This is a second source of truth to maintain.

5. ENVIRONMENT VARIABLES — VERIFIED NAMES AND BEHAVIOR
The .env file was inspected safely. Only variable names and lengths were displayed.

Current state (verified 11 November 2026 after recovery, unchanged in v13):

text
POSTGRES_DB=securebiz
POSTGRES_USER=securebiz_user
POSTGRES_PASSWORD=<15 chars>
APP_DB_USER=securebiz_app
APP_DB_PASSWORD=<16 chars>
VAULT_DEV_ROOT_TOKEN=dev-only-root-token
AUTH_DB_PASSWORD=<64 hex chars>

.env corruption incident and resolution (v11 to v12):

During the v11 session, Add-Content -Path .env -Value "AUTH_DB_PASSWORD=$authPassword" was executed. Because the .env file did not end with a trailing newline, the new line was appended to the end of the last line, producing:

text
VAULT_DEV_ROOT_TOKEN=dev-only-root-tokenAUTH_DB_PASSWORD=<64 chars>

This corrupted both the Vault token and the AUTH_DB_PASSWORD line, causing:

Vault: status 403 enabling transit: invalid token in the API startup;
AUTH_DB_PASSWORD no longer on its own line.

Resolution: the .env file was rebuilt from recovered values using [System.IO.File]::WriteAllLines(), which adds newlines between lines. All 7 lines are now clean. VAULT_DEV_ROOT_TOKEN is exactly dev-only-root-token. AUTH_DB_PASSWORD is exactly 64 hex characters.

Never request or reproduce actual values.

New in v13: the JWT HS256 secret is NOT in .env. It lives in Vault KV at secret/data/securebiz/jwt. This is by design (centralized secret management, audit, rotation).

6. LIVE POSTGRESQL ROLE CONFIGURATION
Verified live on 11 November 2026. Unchanged in v13.

Roles:

Role	LOGIN	SUPERUSER	INHERIT	BYPASSRLS
securebiz_app	Yes	No	No	No
securebiz_auth	Yes	No	Yes	No
securebiz_owner	No	No	Yes	No
securebiz_user	Yes	Yes	Yes	Yes

Additional attributes observed:

securebiz_user has CREATEROLE, CREATEDB and replication privileges.
The other three roles do not have those privileges.
A role-membership inspection involving these four roles returned zero rows.
A dedicated membership query for securebiz_auth returned zero rows.

Semantic note on INHERIT: securebiz_app has INHERIT=No, which is unusual for a runtime role but has been verified. It does not prevent the role from performing its operations. The reason for this setting is not documented in the current handover and would need to be investigated if it becomes relevant.

Semantic note on securebiz_auth: securebiz_auth has INHERIT=Yes (contrary to v7 which reported NOINHERIT). This means it inherits privileges from any roles it belongs to. The membership inspection returned zero rows, so inheritance is currently inert.

Important:

securebiz_app is the current business runtime role.
securebiz_auth is the authentication role (password verification, session management).
securebiz_owner is a non-login owner role.
securebiz_user is a highly privileged superuser.

Never use securebiz_user as a runtime API account.

A grant restriction against securebiz_user is not a meaningful security boundary against a superuser.

7. LIVE SCHEMA PRIVILEGES
Verified live on 11 November 2026. Unchanged in v13.

auth_private
securebiz_auth: USAGE.
securebiz_owner: USAGE.
securebiz_app: no USAGE.
PUBLIC: no listed privileges.
securebiz_user: USAGE and CREATE.

auth_security
securebiz_app: USAGE.
securebiz_owner: USAGE.
securebiz_auth: no USAGE.
PUBLIC: no listed privileges.
securebiz_user: USAGE and CREATE.

auth_session (added v12)
securebiz_auth: USAGE.
securebiz_owner: USAGE.
securebiz_app: no USAGE.
PUBLIC: no privileges.
securebiz_user: owner (implicit).

public
PUBLIC: USAGE.
securebiz_app: USAGE.
securebiz_owner: USAGE.
pg_database_owner: USAGE and CREATE.

No CREATE privilege was listed for the three application/owner roles.

pg_database_owner CREATE must not be interpreted as a grant to every database user.

These findings are schema-level privileges, not proof of table or function privileges.

8. LIVE TABLE OWNERSHIP AND PRIVILEGES
The live ACL query returned 111 rows (before migration 002). After migration 002, auth_session.refresh_tokens is added. Unchanged in v13.

All tables included in that output were owned by:

text
securebiz_user

This included:

text
auth_private.credentials

auth_security.public_keys
auth_security.transaction_context
auth_security.used_jti

public.membership_roles
public.memberships
public.organizations
public.permissions
public.role_permissions
public.roles
public.users

auth_session.refresh_tokens is owned by securebiz_user.

Important:

securebiz_owner is not the table owner in the inspected result.
Do not assume that SECURITY DEFINER functions owned by securebiz_owner automatically bypass RLS or have unrestricted table privileges.

8.1 Credentials table
auth_private.credentials:

Owner: securebiz_user.
Columns: user_id uuid NOT NULL, password_hash text NOT NULL, updated_at timestamptz NOT NULL.
securebiz_owner: SELECT.
No direct table privilege listed for securebiz_auth.
No direct table privilege listed for securebiz_app.
No PUBLIC table privilege listed.
RLS disabled.
FORCE RLS disabled.

New in v13: the table now contains exactly 1 row (the test credential created on 12 November 2026 for user a2c643f2-7212-4693-bc7f-d220cb9cdaf4, email test-user@test.com). The password hash is Argon2id with parameters time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16. The hash itself must never be displayed.

8.2 Security tables
Table	Owner	securebiz_owner privileges	RLS
auth_security.public_keys	securebiz_user	INSERT, SELECT, UPDATE	Disabled
auth_security.transaction_context	securebiz_user	DELETE, INSERT, SELECT, UPDATE	Disabled
auth_security.used_jti	securebiz_user	DELETE, INSERT, SELECT	Disabled

No direct application-role table privileges were listed for these tables.

The application accesses security functionality through database functions.

8.3 Direct privileges for securebiz_app
Table	Direct privileges
public.membership_roles	DELETE, INSERT, SELECT
public.memberships	DELETE, INSERT, SELECT, UPDATE
public.organizations	SELECT
public.permissions	SELECT
public.role_permissions	DELETE, INSERT, SELECT
public.roles	DELETE, INSERT, SELECT, UPDATE
public.users	SELECT

securebiz_app has no privileges on auth_session.refresh_tokens (verified: app_can_select_refresh = f).

The API role has direct DML privileges on several IAM tables.

RLS may constrain affected rows, but the necessity of these grants must be evaluated against actual route behavior and authorization checks.

Do not revoke or change grants until dependencies have been inspected.

8.4 Direct privileges for securebiz_owner
The additional direct privilege query verified the following:

Schema	Table	SELECT	INSERT	UPDATE	DELETE
auth_private	credentials	true	false	false	false
auth_security	public_keys	true	true	true	false
auth_security	transaction_context	true	true	true	true
auth_security	used_jti	true	true	false	true
public	membership_roles	true	false	false	false
public	memberships	true	false	false	false
public	organizations	true	false	false	false
public	permissions	false	false	false	false
public	role_permissions	true	false	false	false
public	roles	true	false	false	false
public	users	true	false	false	false

Schema	Table	SELECT
auth_session	refresh_tokens	true

This confirms that securebiz_owner has read access to several public IAM tables and write access to the security tables, subject to other PostgreSQL security mechanisms.

It does not have any listed direct privilege on public.permissions. The v9 Section 12.2 description listing permissions among the joined tables in app_has_permission should be treated as incomplete or inaccurate, because the function could not read that table under securebiz_owner without an explicit privilege.

securebiz_owner is NOLOGIN, non-superuser and does not have BYPASSRLS.

8.5 Direct privileges for securebiz_auth
A dedicated privilege query was executed against auth_private.credentials.

Verified results:

Privilege	securebiz_auth on auth_private.credentials
SELECT	false
INSERT	false
UPDATE	false
DELETE	false
TRUNCATE	false
Schema USAGE on auth_private	true
Schema CREATE on auth_private	false

securebiz_auth on auth_session.refresh_tokens:

Privilege	securebiz_auth on auth_session.refresh_tokens
SELECT	true
INSERT	true
UPDATE	true
DELETE	false
Schema USAGE on auth_session	true

securebiz_auth EXECUTE on auth_session.get_user_status(UUID): true.

The role can use the schema but cannot directly read or modify the credentials table through the checked table privileges.

This is consistent with the intended restricted authentication-function design.

8.6 Default privileges inspection — verified 11 November 2026
A dedicated query was executed against pg_default_acl:

sql
SELECT pg_get_userbyid(defaclrole) AS grantor_role,
       defaclnamespace::regnamespace AS schema_name,
       defaclobjtype AS object_type,
       defaclacl AS acl
FROM pg_default_acl
ORDER BY schema_name, object_type;

Result: 5 rows.

Grantor	Schema	Object type	ACL
securebiz_user	pgsodium	S (sequence)	pgsodium_keyholder=rwU
securebiz_user	pgsodium	r (table)	pgsodium_keyholder=arwdDxt
securebiz_user	pgsodium_masks	S	pgsodium_keyiduser=rwU
securebiz_user	pgsodium_masks	f (function)	pgsodium_keyiduser=X
securebiz_user	pgsodium_masks	r	pgsodium_keyiduser=arwdDxt

All 5 entries concern only the pgsodium and pgsodium_masks extension schemas and benefit only pgsodium_keyholder and pgsodium_keyiduser. No entry involves public, auth_private, auth_security, or auth_session. No entry grants any privilege to securebiz_app, securebiz_auth, or securebiz_owner.

Consequence: the creation of future tables in application schemas will not inherit any implicit privilege for the application or authentication roles. Explicit GRANT statements will always be required.

Do not modify the pgsodium / pgsodium_masks default privileges; they are extension-internal.

8.7 Scope limitation
The 111-row query did not establish all privileges for:

sequences;
views;
materialized views;
functions;
column-level grants;
default privileges;
every effective execution context.

Do not claim that the entire database privilege model has been audited.

9. LIVE RLS FLAGS
Verified live on 11 November 2026. Unchanged in v13.

Table	RLS enabled	FORCE RLS
public.membership_roles	Yes	Yes
public.memberships	Yes	Yes
public.organizations	Yes	Yes
public.role_permissions	Yes	Yes
public.roles	Yes	Yes
public.users	Yes	Yes
public.permissions	No	No
auth_private.credentials	No	No
auth_security.public_keys	No	No
auth_security.transaction_context	No	No
auth_security.used_jti	No	No
auth_session.refresh_tokens	No	No

Do not disable RLS or FORCE RLS.

Note: auth_session.refresh_tokens has RLS disabled. This is intentional: it is protected by strict ACLs (only securebiz_auth has SELECT/INSERT/UPDATE) and is not part of the tenant-scoped data model. It is a session store, not a tenant table.

10. LIVE RLS POLICY INSPECTION — COMPLETED
Status: COMPLETED on 11 November 2026. Unchanged in v13.

The live PostgreSQL policy query was executed:

powershell
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check FROM pg_policies WHERE schemaname IN ('public', 'auth_private', 'auth_security') ORDER BY schemaname, tablename, policyname;"

The query returned 22 policies.

Do not ask the user to execute this query again as an initial inspection.

10.1 Policy distribution
All 22 returned policies were in the public schema and were PERMISSIVE.

Table	Application policies	Owner policies	Total
membership_roles	3	1	4
memberships	4	1	5
organizations	1	1	2
role_permissions	3	1	4
roles	4	1	5
users	1	1	2
Total	16	6	22

No policy was returned for:

auth_private.credentials;
auth_security.public_keys;
auth_security.transaction_context;
auth_security.used_jti;
public.permissions;
auth_session.refresh_tokens.

This is consistent with the RLS flags previously observed for those tables.

10.2 Owner policies
Six owner policies were observed, one on each of the six tenant-sensitive public IAM tables.

Each owner policy is:

text
PERMISSIVE
FOR ALL
TO securebiz_owner
USING (true)
WITH CHECK (true)

These policies grant the effective securebiz_owner role access to all rows on the corresponding tables, subject to other PostgreSQL security rules.

They do not mean that securebiz_app automatically receives the same access.

They are particularly important when evaluating SECURITY DEFINER functions executing as securebiz_owner.

Do not remove them without first establishing which security routines depend on them and how their execution context is constrained.

10.3 Application policies
public.membership_roles
Three application policies were observed:

SELECT: context organization and roles:read.
INSERT: context organization and roles:update.
DELETE: context organization and roles:update.

public.memberships
Four application policies were observed:

SELECT: context organization and users:read.
INSERT: context organization and users:invite.
UPDATE: context organization and users:update, with corresponding USING and WITH CHECK conditions.
DELETE: context organization and users:deactivate.

public.organizations
One application SELECT policy was observed.

It restricts rows to the organization identifier obtained from the signed tenant context.

The observed condition did not include an explicit app_has_permission check.

public.role_permissions
Three application policies were observed:

SELECT: context organization and roles:read.
INSERT: context organization and roles:update, with verification that the referenced role belongs to the same organization and is not a system role.
DELETE: context organization and roles:update, with verification that the referenced role belongs to the same organization and is not a system role.

public.roles
Four application policies were observed:

SELECT: context organization and roles:read.
INSERT: context organization, non-system role and roles:create.
UPDATE: context organization, non-system role and roles:update.
DELETE: context organization, non-system role and roles:delete.

public.users
One application SELECT policy was observed.

It checks users:read and the existence of an active membership for the target user in the signed context organization.

10.4 Verification of absence of RESTRICTIVE and PUBLIC-assigned policies — verified 11 November 2026
Two additional read-only queries were executed:

RESTRICTIVE policies: 0 rows. The effective model is purely PERMISSIVE with OR semantics.

sql
SELECT schemaname, tablename, policyname, permissive, roles, cmd
FROM pg_policies
WHERE schemaname IN ('public', 'auth_private', 'auth_security')
  AND permissive = 'RESTRICTIVE'
ORDER BY schemaname, tablename, policyname;

Policies assigned to PUBLIC or unexpected roles: 0 rows.

sql
SELECT schemaname, tablename, policyname, permissive, roles, cmd
FROM pg_policies
WHERE schemaname IN ('public', 'auth_private', 'auth_security')
  AND NOT (roles && ARRAY['securebiz_app','securebiz_owner']::name[])
ORDER BY schemaname, tablename, policyname;

All 22 policies are assigned exclusively to securebiz_app or securebiz_owner.

10.5 PostgreSQL policy semantics
All 22 policies returned by the inspection were PERMISSIVE.

PostgreSQL combines applicable PERMISSIVE policies with OR semantics.

Applicable RESTRICTIVE policies, if present, are combined with AND semantics and the permissive result.

The six owner policies are therefore an important part of the effective access model.

The existence of an owner policy does not automatically establish that the owner role can bypass FORCE ROW LEVEL SECURITY. The actual effective role, table privileges and applicable policies must all be considered.

10.6 RLS assessment
Positive findings:

Six important IAM tables have RLS enabled and FORCE RLS enabled.
Application policies use the signed context organization identifier.
Several policies also require an explicit RBAC permission.
Role and role-permission policies include restrictions concerning system roles.
The users SELECT policy checks active membership.
No RESTRICTIVE policy exists.
No policy is assigned to PUBLIC or any unexpected role.

Points requiring continued review:

The owner policies intentionally allow all-row access to securebiz_owner.
SECURITY DEFINER routines owned by securebiz_owner must be reviewed individually (already done for the 9 project routines, see Section 13).
The absence of RLS on public.permissions means its protection depends on privileges and application behavior.
The security tables are protected by function access and table ACLs rather than RLS.
The organizations SELECT policy does not explicitly invoke app_has_permission.
The application routes must be checked to establish whether they invoke the required authorization checks.
The policies' exact SQL expressions must be consulted from the actual command output before making any change.

No RLS policy has been modified as part of these inspections.

11. VAULT AND SIGNED TENANT CONTEXT
Vault Transit key observed:

text
securebiz-context

Relevant files:

text
app/core/vault.py
app/services/context_signing.py

The canonical signed JSON payload contains:

issuer: securebiz-api;
audience: securebiz-postgres;
subject: user UUID;
organization UUID;
JTI generated using UUID4;
issued-at timestamp;
expiration timestamp, approximately 30 seconds later.

The payload is serialized using compact, sorted JSON.

The signing service returns serialized payload, signature bytes, Vault version and key version.

The signing service does not independently establish caller identity or prove membership.

Database function:

text
auth_security.securebiz_install_context(...)

The database function verifies the signed context, validates claims and checks active user, organization and membership before installing the context.

Replay protection uses JTI tracking.

Preserve the transaction-binding and replay-prevention mechanisms.

Vault currently runs in development mode with -dev-root-token-id=dev-only-root-token. The root token is static and does not change on container recreation.

Note: The root token dev-only-root-token is a development-only root token. In production, the API must use a restricted token with a policy granting only:

read on transit/sign/securebiz-context (for context signing);
read on secret/data/securebiz/jwt (for JWT HS256 secret);
read on transit/keys/securebiz-context (to verify key existence).

The current init_vault_key() also performs POST /v1/sys/mounts/transit and POST /v1/transit/keys/{KEY_NAME}, which are admin operations that must be separated from runtime in production. This is a known security debt (Section 24.2).

11.1 app/core/vault.py — updated in v13
Full code is preserved in the transcript. Key points:

VAULT_TOKEN is read from environment, RuntimeError immediately if missing (fail-fast at module load).
init_vault_key() is idempotent: handles 400 already mounted, 404 key absent -> create, 200 key exists, 403 token, 5xx.
sign_payload() validates the signature output: 64 bytes exactly, prefix vault:v, key_version >= 1.
requests.exceptions.RequestException is caught and re-raised as RuntimeError.

New in v13: get_jwt_secret() is implemented.
Signature: def get_jwt_secret() -> tuple[bytes, str, bytes | None, str | None]
Returns: (current_secret, current_kid, previous_secret, previous_kid)
- current_secret: 32 bytes (decoded from 64 hex chars)
- current_kid: non-empty str
- previous_secret: 32 bytes or None
- previous_kid: non-empty str or None
The secret is cached at module level. invalidate_jwt_secret_cache() clears the cache.
Reads Vault KV-v2 at secret/data/securebiz/jwt via GET /v1/secret/data/securebiz/jwt.
Validates:
- current: 64 hex chars, decodes to exactly 32 bytes.
- current_kid: non-empty string.
- previous and previous_kid: both present or both absent.
All validation errors raise RuntimeError with generic messages (no secret value, no response body). The original exception is NOT chained (from None) to avoid leaking response bodies into tracebacks.
Logs only current_kid and rotation_in_progress flag. Never logs the secret.

Verified 12 November 2026:
- current_secret: 32 bytes.
- current_kid: v2 (cosmetic; the actual Vault version is 3 due to a double rotation).
- previous_secret: None.
- previous_kid: None.

Known debt: init_vault_key() mixes Vault provisioning (mount engine, create key) with runtime. In production, the API should not be able to mount a secrets engine or create a key. This is documented in Section 24.2.

11.2 app/services/context_signing.py — analyzed in v12, unchanged in v13
Full code is preserved in the transcript. Key points:

Separation is clean: no DB, no HTTP handler, no auth validation.
_validate_uuid(): strict (non-empty, valid UUID, rejects nil UUID).
build_payload(): canonical JSON with iss, aud, sub, org, jti (UUID4), iat, exp. ensure_ascii=True, separators=(",", ":"), sort_keys=True.
CONTEXT_TTL_SECONDS = 30, MAX_CONTEXT_TTL_SECONDS = 60 (constants).
sign_context() returns (payload_json, sig_bytes, vault_version, key_version).
The docstring explicitly forbids authentication/JWT logic in this file.

Confirmation: sign_context() does not verify that the user exists or that the membership is active. This is by design — PostgreSQL (securebiz_install_context) performs that verification at installation time. A malicious caller can generate a signed payload with arbitrary UUIDs; PostgreSQL rejects it at install if the user/org/membership is inactive. The signature proves API origin, not content legitimacy.

11.3 app/main.py — updated in v13
Full code is preserved in the transcript. Key points:

FastAPI application initialization, routers registered.
@app.on_event("startup") -> init_vault_key().
/health uses get_database_session() and SELECT 1, returns 503 on OperationalError/OSError.
Root endpoint minimal.

New in v13: the auth router is registered.

The imports section now includes:
from app.api.routes.auth import router as auth_router

And the registration section:
app.include_router(auth_router)

The full router order is:
app.include_router(organizations_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(auth_router)

Verified 12 November 2026: /openapi.json returns 8 paths:
- / (root)
- /health
- /users
- /organizations/me
- /roles
- /auth/login
- /auth/refresh
- /auth/logout

Known technical debt (Section 24.2):

@app.on_event("startup") is deprecated in FastAPI 0.109+. Should migrate to lifespan=.
init_vault_key() mixes Vault provisioning with runtime. Should be separated in production.
startup_event() has no error handling around init_vault_key(). If Vault is unavailable, the API crashes (fail-closed, intentional but not graceful).

12. DATABASE SECURITY FUNCTIONS — FIVE CRITICAL FUNCTIONS ALREADY INSPECTED
Status: The five functions listed below have already been inspected individually. Unchanged in v13.

The inspection included:

schema;
function name;
identity arguments;
owner;
SECURITY DEFINER flag;
volatility;
configured function settings;
EXECUTE ACL;
function definition.

The inspection query was:

powershell
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -P pager=off -x -c "SELECT n.nspname AS schema_name, p.proname AS function_name, pg_get_function_identity_arguments(p.oid) AS arguments, pg_get_userbyid(p.proowner) AS function_owner, p.prosecdef AS security_definer, p.provolatile AS volatility, p.proconfig AS function_settings, p.proacl AS execute_acl, pg_get_functiondef(p.oid) AS function_definition FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE (n.nspname = 'auth_private' AND p.proname = 'authenticate') OR (n.nspname = 'auth_security' AND p.proname IN ('app_has_permission', 'securebiz_install_context', 'prevent_system_role_modification', 'securebiz_get_context')) ORDER BY n.nspname, p.proname, arguments;"

12.1 auth_private.authenticate(VARCHAR)
Verified observations:

Owner: securebiz_owner.
SECURITY DEFINER: true.
Volatility: STABLE.
Search path: pg_catalog, pg_temp.
EXECUTE ACL includes securebiz_owner and securebiz_auth.
Returns TABLE(user_id uuid, password_hash text, status character varying).
The function retrieves authentication data from public.users and auth_private.credentials.
Comparison: WHERE pg_catalog.lower(u.email) = pg_catalog.lower(p_email).
Returns no row if the email is unknown (fetchone returns None in Python).

It does not:

verify the supplied password;
issue a JWT;
establish a complete authentication session.

Do not describe this function as a complete authentication implementation.

Do not expose or reproduce the password hash.

12.2 auth_security.app_has_permission(TEXT)
Verified observations:

Owner: securebiz_owner.
SECURITY DEFINER: true.
Volatility: VOLATILE.
Search path: pg_catalog, pg_temp.
EXECUTE ACL: owner and securebiz_app.

The SQL implementation joins memberships, membership_roles, roles, role_permissions, and organizations. The v9 Section 12.2 description listing permissions among joined tables is likely inaccurate; the ACL of securebiz_owner on public.permissions is absent (Section 8.4), which would prevent any direct read of that table.

It uses the user and organization identifiers obtained from securebiz_get_context.

It checks:

active membership;
active organization;
requested permission code.

The function is explicitly anchored to the current tenant context.

Its existence does not prove that every API route invokes it.

12.3 auth_security.securebiz_install_context(...)
Verified in the earlier inspection, unchanged in v13.

The function:

validates the signed context;
verifies the Ed25519 signature;
checks issuer and audience;
validates claim types and formats;
checks timestamps and a short maximum validity period (60 seconds);
checks active user;
checks active organization and membership;
applies JTI replay protection;
installs the transaction-bound tenant context.

All failure paths use RAISE EXCEPTION (no RETURN FALSE). The observed messages include:
- Missing cryptographic input
- Payload exceeds maximum permitted size
- Invalid Ed25519 signature length
- A context has already been installed in this transaction
- Unknown or revoked signing key
- Invalid Ed25519 signature
- Payload must be a JSON object
- Missing claim or invalid claim type
- iat and exp must be positive integer Unix timestamps
- Invalid UUID or timestamp claim
- Invalid issuer
- Invalid audience
- Invalid JTI
- Token issued too far in the future
- Token expiration must be after issuance
- Token lifetime exceeds 60 seconds
- Token expired
- Inactive or unauthorized user membership
- Token replay detected

These messages are used in get_authenticated_tenant_context (Section 19.4) to classify SQL errors:
- Inactive or unauthorized user membership -> 403
- Token expired, Unknown or revoked signing key -> 503
- All others -> 500 (including Token replay detected and Invalid Ed25519 signature, which are security anomalies, not unavailability).

Preserve its signature verification, membership verification, anti-replay and transaction-binding behavior.

Do not invent or alter its exact argument list without consulting the live definition.

12.4 auth_security.securebiz_get_context(...)
Verified in the earlier inspection, unchanged in v13.

The function:

restricts access to the expected context fields;
supports the user and organization identifiers;
checks the context's transaction binding;
checks expiration;
checks that the context has not been cleaned up.

Additional verified fact (11 November 2026): securebiz_get_context is called 20 times inside the RLS policies defined in database/migrations/001_iam_multitenant_v8.sql (lines 611, 613, 874, 887, 897, 906, 915, 920, 929, 938, 947, 957, 963, 973, 983, 992, 1001, 1010, 1019, 1035). This is its primary invocation path outside app/api/dependencies.py.

Performance note: in the global inventory, securebiz_get_context is observed with volatility v (VOLATILE), not STABLE. The function therefore cannot benefit from plan-level caching when invoked by RLS policies. Each evaluation is a fresh call. This has a performance implication but is not a security finding.

Do not assume it is a general-purpose arbitrary session-variable reader.

Its exact signature and ACL should be consulted from the prior inspection if a targeted issue requires them.

12.5 auth_security.prevent_system_role_modification()
Verified observations:

Owner: securebiz_owner.
SECURITY DEFINER: false.
Volatility: VOLATILE.
Search path: pg_catalog, pg_temp.
It is a trigger function.

The function checks:

sql
current_user = 'securebiz_app'

The trigger protection therefore depends partly on the effective database user at trigger execution time.

Potential concern:

When a write operation executes inside a SECURITY DEFINER function owned by securebiz_owner, current_user may be securebiz_owner, rather than securebiz_app.

This must be considered when assessing privileged write paths.

The complete trigger function definition was inspected, but the previously pasted transcript was truncated near its end. Do not invent unverified code details.

13. GLOBAL SECURITY DEFINER INVENTORY AND ADDITIONAL FUNCTION INSPECTIONS — COMPLETED
Status: COMPLETED on 11 November 2026. Unchanged in v13.

The global inventory was executed. Its output returned 33 non-system SECURITY DEFINER routines (before migration 002).

13.1 Global inventory result
The query used was:

powershell
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -P pager=off -c "SELECT n.nspname AS schema_name, p.proname AS routine_name, pg_get_function_identity_arguments(p.oid) AS arguments, pg_get_userbyid(p.proowner) AS routine_owner, l.lanname AS language, p.prokind AS routine_kind, p.provolatile AS volatility, p.proconfig AS function_settings FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prosecdef = true ORDER BY n.nspname, p.proname, arguments;"

Result (pre-002):

Category	Number of routines
Application routines in auth_private and auth_security	8
Extension routines in pgsodium	25
Total	33

The eight application routines are:

auth_private.authenticate(p_email character varying)
auth_security.app_has_permission(p_permission_code text)
auth_security.securebiz_cleanup_context()
auth_security.securebiz_get_context(p_field text)
auth_security.securebiz_install_context(p_payload text, p_signature bytea, p_key_id character varying)
auth_security.securebiz_purge_expired_security_data()
auth_security.securebiz_register_public_key(p_kid character varying, p_public_key bytea)
auth_security.securebiz_revoke_public_key(p_kid character varying)

After migration 002, one new SECURITY DEFINER function:

auth_session.get_user_status(p_user_id UUID)

Total after v12: 9 application routines + 25 pgsodium = 34 SECURITY DEFINER routines.

The 25 pgsodium routines are extension-owned (pgsodium_keymaker or securebiz_user). They are out of scope for the application security review. Their existence is expected. They must not be modified.

13.2 Ownership and search path of application routines
All nine application SECURITY DEFINER routines are owned by securebiz_owner with search_path=pg_catalog, pg_temp.

This is a useful hardening characteristic because the functions do not rely on an uncontrolled default search path.

However, a safe search path alone does not prove that a function is safe. Its SQL statements, table access, input validation, execution grants and tenant constraints must also be evaluated.

13.3 auth_security.securebiz_cleanup_context()
Full definition (inspected in v11, unchanged):

plpgsql
CREATE OR REPLACE FUNCTION auth_security.securebiz_cleanup_context()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    UPDATE auth_security.transaction_context
       SET cleaned_at = pg_catalog.clock_timestamp()
     WHERE txid = pg_catalog.pg_current_xact_id()
       AND cleaned_at IS NULL;
END;
$function$;

Owner securebiz_owner.
SECURITY DEFINER: true.
Search path: pg_catalog, pg_temp.
EXECUTE ACL: securebiz_owner, securebiz_app.
Targets the current transaction only (txid = pg_current_xact_id()).
Idempotent (cleaned_at IS NULL).
No dynamic SQL, no parameters.

The function is used by the application dependency after the route has completed its work. The database function definition and ACL have been inspected. Its complete runtime behavior under every transaction failure path has not yet been tested.

13.4 auth_security.securebiz_purge_expired_security_data()
Full definition (inspected in v11, unchanged):

plpgsql
CREATE OR REPLACE FUNCTION auth_security.securebiz_purge_expired_security_data()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    DELETE FROM auth_security.transaction_context
     WHERE expires_at < pg_catalog.clock_timestamp() - INTERVAL '10 minutes';

    DELETE FROM auth_security.used_jti
     WHERE used_at < pg_catalog.clock_timestamp() - INTERVAL '10 minutes';
END;
$function$;

Owner securebiz_owner.
SECURITY DEFINER: true.
EXECUTE ACL: securebiz_owner only.
Explicit time filter with 10-minute margin.
No dynamic SQL, no parameters.
Not executable by securebiz_app or securebiz_auth.

The 10-minute margin covers clock skew and in-flight requests. A JTI that is still within its validity window is never deleted by this function.

Its invocation mechanism remains open: no scheduled task, administrative process or provisioning caller has yet been established (see Section 26.3 in v12; unchanged in v13).

Do not grant the application role EXECUTE merely to make the function easier to call.

13.5 auth_security.securebiz_register_public_key(VARCHAR, BYTEA)
Full definition (inspected in v11, unchanged):

plpgsql
CREATE OR REPLACE FUNCTION auth_security.securebiz_register_public_key(
    p_kid character varying, p_public_key bytea)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    IF p_kid IS NULL OR length(btrim(p_kid)) = 0 THEN
        RAISE EXCEPTION 'Key identifier is required';
    END IF;

    IF p_public_key IS NULL OR octet_length(p_public_key) <> 32 THEN
        RAISE EXCEPTION 'Ed25519 public key must contain exactly 32 bytes';
    END IF;

    INSERT INTO auth_security.public_keys (kid, public_key)
    VALUES (p_kid, p_public_key);
END;
$function$;

Owner securebiz_owner.
SECURITY DEFINER: true.
EXECUTE ACL: securebiz_owner only.
Validates kid non-empty and Ed25519 key = 32 bytes.
No ON CONFLICT (fail-closed).
Not executable by securebiz_app or securebiz_auth.

The trusted administrative provisioning mechanism that calls this function has not yet been identified (see v12 Section 26.2, unchanged in v13). Do not expose this function to the business runtime role without a separate security design.

13.6 auth_security.securebiz_revoke_public_key(VARCHAR)
Full definition (inspected in v11, unchanged):

plpgsql
CREATE OR REPLACE FUNCTION auth_security.securebiz_revoke_public_key(p_kid character varying)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
BEGIN
    UPDATE auth_security.public_keys
       SET revoked_at = pg_catalog.clock_timestamp()
     WHERE kid = p_kid
       AND revoked_at IS NULL;

    RETURN FOUND;
END;
$function$;

Owner securebiz_owner.
SECURITY DEFINER: true.
EXECUTE ACL: securebiz_owner only.
Idempotent (revoked_at IS NULL).
Preserves audit trail (revoked_at, no DELETE).
Returns FOUND.
No dynamic SQL.
Not executable by securebiz_app or securebiz_auth.

The trusted administrative revocation process has not yet been identified (see v12 Section 26.2, unchanged in v13).

13.7 Effective EXECUTE privileges on the eight pre-v12 application functions
A dedicated effective privilege query was executed:

powershell
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -P pager=off -c "SELECT n.nspname AS schema_name, p.proname AS function_name, pg_get_function_identity_arguments(p.oid) AS arguments, has_function_privilege('securebiz_app', p.oid, 'EXECUTE') AS app_can_execute, has_function_privilege('securebiz_auth', p.oid, 'EXECUTE') AS auth_can_execute, has_function_privilege('securebiz_owner', p.oid, 'EXECUTE') AS owner_can_execute FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('auth_private', 'auth_security') AND p.prosecdef = true ORDER BY n.nspname, p.proname, arguments;"

Verified result:

Function	securebiz_app	securebiz_auth	securebiz_owner
auth_private.authenticate(...)	false	true	true
auth_security.app_has_permission(...)	true	false	true
auth_security.securebiz_cleanup_context()	true	false	true
auth_security.securebiz_get_context(...)	true	false	true
auth_security.securebiz_install_context(...)	true	false	true
auth_security.securebiz_purge_expired_security_data()	false	false	true
auth_security.securebiz_register_public_key(...)	false	false	true
auth_security.securebiz_revoke_public_key(...)	false	false	true

This confirms the intended separation at the function EXECUTE level:

securebiz_auth can execute the authentication lookup function.
securebiz_app can execute the context, cleanup and permission functions required by the business application.
Neither runtime role can execute the administrative purge or public-key management functions.
securebiz_owner can execute all eight application routines.

These are effective EXECUTE checks for the three specified roles. They do not establish every possible privilege path in the database.

13.8 Interpretation of the application function boundary
The observed function boundary is consistent with a separation between:

Authentication operations
text
securebiz_auth
    |
    +--> auth_private.authenticate(...)
    +--> auth_session.get_user_status(...)         (new in v12)
    +--> auth_session.refresh_tokens (DML)         (new in v12, direct table access)

Business application and tenant-context operations
text
securebiz_app
    |
    +--> securebiz_install_context(...)
    +--> securebiz_get_context(...)
    +--> securebiz_cleanup_context()
    +--> app_has_permission(...)

Administrative security operations
text
securebiz_owner
    |
    +--> securebiz_purge_expired_security_data()
    +--> securebiz_register_public_key(...)
    +--> securebiz_revoke_public_key(...)
    +--> get_user_status(...) (owner, not caller)

This is an interpretation of the observed EXECUTE ACLs. It does not prove that the corresponding administrative caller or provisioning workflow exists.

13.9 Remaining open questions after the inventory
The global inventory is complete, but the complete privileged-routine security review is not.

Still to establish:

Whether all 25 pgsodium routines are expected and correctly configured for the installed extension. (Answer: yes, out of scope, do not modify.)
Whether any application routine invokes another privileged routine indirectly. (No static evidence found. Dynamic test pending.)
Whether any application routine uses dynamic SQL. (No dynamic SQL found in any of the 9 application functions.)
Whether all privileged routines constrain their inputs and data access appropriately. (Verified for the 4 newly inspected functions in v11 and the new get_user_status in v12.)
Whether administrative key registration and revocation have a trusted operational caller. (See v12 Section 26.2, unchanged in v13.)
Whether expired security-data cleanup is scheduled or manually administered. (Open.)
Whether the effective execution context of each routine interacts safely with FORCE RLS and the owner policies. (Static analysis done. Dynamic test pending.)

13.10 auth_session.get_user_status(UUID) — added v12
Verified observations:

Owner: securebiz_owner.
SECURITY DEFINER: true.
Volatility: VOLATILE (plpgsql).
Search path: pg_catalog, pg_temp.
EXECUTE ACL: securebiz_owner, securebiz_auth.
PUBLIC has no EXECUTE.

Full definition:

plpgsql
CREATE OR REPLACE FUNCTION auth_session.get_user_status(p_user_id UUID)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF p_user_id IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN (SELECT u.status FROM public.users AS u WHERE u.id = p_user_id);
END;
$$;

Purpose: Read public.users.status without giving securebiz_auth direct access to public.users (which is protected by FORCE ROW LEVEL SECURITY and requires a tenant context, unavailable during /auth/refresh).

Why SECURITY DEFINER is required: securebiz_auth has no USAGE on public and no SELECT on public.users. Only securebiz_owner can read public.users without a tenant context (via the owner_users_policy with USING (true)).

Validation performed:

function_owner = securebiz_owner (verified).
security_definer = t (verified).
proconfig = {search_path=pg_catalog, pg_temp} (verified).
auth_can_exec = t (verified).
app_can_exec = f (verified).
owner_can_exec = t (verified).

Note: the function returns NULL if the user does not exist. The Python caller must treat NULL as "user not found or unauthorized".

14. TRIGGER INSPECTION — COMPLETED
Unchanged in v13.

The live trigger inspection targeted:

text
public.roles
public.role_permissions
public.membership_roles

The query inspected:

schema;
table;
trigger name;
trigger-function owner;
trigger-function name;
enabled state;
internal/custom status;
trigger definition.

The custom trigger identified was:

text
roles_system_protection

It is attached to:

text
public.roles

It invokes:

text
auth_security.prevent_system_role_modification()

Previously observed definition:

text
BEFORE INSERT OR UPDATE OR DELETE

Observed state:

enabled;
non-internal;
SECURITY INVOKER trigger function.

Other entries in the result included internal foreign-key triggers.

The output pasted in the historical transcript was truncated after part of the trigger listing. Do not claim to have independently revalidated every returned trigger row from that truncated text.

14.1 Security concern
The trigger function checks whether:

sql
current_user = 'securebiz_app'

This may behave differently when an operation is executed through a SECURITY DEFINER function owned by securebiz_owner.

Do not modify the trigger until all write paths and effective execution contexts are understood.

15. SEARCH FOR ROUTINES EXPLICITLY WRITING TO public.roles — COMPLETED
Unchanged in v13.

A search was performed for routine definitions containing explicit statements matching:

INSERT INTO roles;
UPDATE roles;
DELETE FROM roles;
equivalent references using public.roles.

The first attempt failed because pg_get_functiondef() was evaluated for aggregate routines.

The query was corrected to exclude aggregates using:

sql
p.prokind <> 'a'

The corrected search returned:

text
(0 rows)

This establishes only that the inspected routine definitions did not match the search pattern.

It does not exclude:

dynamic SQL;
indirect function calls;
writes performed by API application code;
procedures not covered by the search;
differently constructed SQL statements;
direct DML executed by a database role.

Do not interpret the zero-row result as proof that no role-writing path exists.

The additional global SECURITY DEFINER inventory does not change this limitation: the static search and the global inventory answer different questions.

16. GLOBAL SECURITY DEFINER INVENTORY — COMPLETED
Status: COMPLETED on 11 November 2026. Unchanged in v13.

The complete global inventory has now been executed and its output supplied.

Result:

text
33 routines (pre-002)
34 routines (post-002, with auth_session.get_user_status)

Breakdown (post-002):

text
9 application SECURITY DEFINER routines
25 pgsodium SECURITY DEFINER routines

The nine application routines are listed in Section 13.1 and Section 13.10.

All nine application routines are owned by securebiz_owner and configured with:

text
search_path=pg_catalog, pg_temp

The 25 extension routines belong to pgsodium, with owners observed as pgsodium_keymaker or securebiz_user. They are out of scope for the application security review. Do not modify them.

Do not execute the global inventory query again as the next operation.

17. app/main.py — COMPLETE INSPECTION
The complete file was supplied and inspected on 11 November 2026, and updated in Priority 5 (12 November 2026).

Observed (v12 base):

FastAPI application initialization;
registration of users, organizations and roles routers;
startup handler using @app.on_event("startup");
call to init_vault_key() during startup;
root endpoint;
/health endpoint using the business database session and SELECT 1.

The health endpoint catches database connection errors and returns HTTP 503.

No user, organization or membership provisioning was visible in this file.

New in v13 (Priority 5):

Import added:
from app.api.routes.auth import router as auth_router

Registration added:
app.include_router(auth_router)

The full router order is now:
- organizations_router
- users_router
- roles_router
- auth_router

Verified 12 November 2026 via /openapi.json:
Total paths: 8
- /
- /health
- /users
- /organizations/me
- /roles
- /auth/login
- /auth/refresh
- /auth/logout

Known technical debt (Section 24.2):

@app.on_event("startup") is deprecated in FastAPI 0.109+. Should migrate to lifespan=.
init_vault_key() mixes Vault provisioning (mount engine, create key) with runtime. Should be separated in production.
startup_event() has no error handling around init_vault_key(). If Vault is unavailable, the API crashes (fail-closed, intentional but not graceful).

Do not modify main.py during the current inspection phase unless authorized.

18. API ROUTES — INSPECTED AND EXTENDED IN v13
18.1 Users
File:

text
app/api/routes/users.py

Observed (unchanged since v12):

text
GET /users

Query:

sql
SELECT id, email, status
FROM public.users
ORDER BY email;

The route uses:

python
Depends(get_tenant_context)

Its docstring refers to RLS and users:read, but effective route-level permission enforcement must be established from the actual code and database policies.

No user-creation endpoint was observed.

IMPORTANT: this route still uses the debug-header dependency (X-Debug-User-Id, X-Debug-Org-Id). It has NOT been migrated to get_authenticated_tenant_context (JWT + X-Organization-Id). Migration is Priority 6.

18.2 Organizations
File:

text
app/api/routes/organizations.py

Observed (unchanged since v12):

text
GET /organizations/me

Query:

sql
SELECT id, name, slug
FROM public.organizations
LIMIT 1;

Returns 404 when no organization is found.

No organization-creation endpoint was observed.

IMPORTANT: this route still uses the debug-header dependency. Migration is Priority 6.

18.3 Roles
File:

text
app/api/routes/roles.py

Observed (unchanged since v12):

text
GET /roles

Query:

sql
SELECT id, name
FROM public.roles
ORDER BY name;

The docstring refers to RLS and roles:read, but actual enforcement still needs to be established.

No role-creation endpoint was observed.

IMPORTANT: this route still uses the debug-header dependency. Migration is Priority 6.

18.4 Dependency contract in routes — verified 11 November 2026
A read-only search across app/api/routes/*.py was performed:

powershell
$patterns = '\.commit\(|\.rollback\(|\.close\(|with\s+connection|with\s+conn\b'
Get-ChildItem .\app\api\routes -Recurse -File -Filter *.py |
    Select-String -Pattern $patterns

Only three matches were returned, all of the form with connection.cursor() as cur: (in organizations.py:27, roles.py:25, users.py:25). These are the psycopg cursor context manager, not a connection context manager. They do not commit, rollback, or close the connection.

No occurrence of connection.commit(), connection.rollback(), connection.close(), or with connection: as a bare connection context manager was found.

A second read-only search was performed:

powershell
$patterns2 = 'get_raw_connection|get_database_connection|get_database_session|psycopg\.connect'
Get-ChildItem .\app\api\routes -Recurse -File -Filter *.py |
    Select-String -Pattern $patterns2

Result: no matches. No route opens its own connection.

Conclusion: the dependency contract — routes do not manage transactions and do not open connections — is respected empirically by all three read-only routes.

Reserve: any future write route must be submitted to the same verification.

18.5 NEW in v13 — Authentication routes
File:

text
app/api/routes/auth.py

Created in Priority 5. 12752 bytes, 375 lines, LF line endings, no BOM.

Router:
python
router = APIRouter(prefix="/auth", tags=["Authentication"])

Three endpoints, all POST:

POST /auth/login
Purpose: verify email + password, issue an access JWT and a refresh cookie.
Flow:
1. get_auth_connection() (securebiz_auth).
2. SELECT user_id, password_hash, status FROM auth_private.authenticate(%s) with request.email.
3. If no row -> dummy Argon2id verify (_verify_password(_DUMMY_PASSWORD_HASH, request.password)) then raise 401 "Invalid credentials." (timing equalization, no enumeration).
4. If row: verify password with _verify_password(password_hash, request.password). Failure -> 401 "Invalid credentials.".
5. If db_status != "active" -> 401 "Invalid credentials.".
6. create_access_token(str(user_id)) -> 200 JWT.
7. create_refresh_family(str(user_id), user_agent=None, ip_address=None) -> (raw_token, family_id). On RefreshTokenDatabaseError -> 503.
8. response.set_cookie("refresh_token", raw_token, max_age=604800, path="/auth", secure=True, httponly=True, samesite="strict").
9. Return TokenResponse(access_token, token_type="bearer", expires_in=settings.JWT_ACCESS_TTL_SECONDS).

POST /auth/refresh
Purpose: rotate the refresh token and issue a new access JWT.
Flow:
1. If no refresh_token cookie -> 401 "Refresh token required.".
2. rotate_refresh_token(refresh_token). On RefreshTokenError -> 401 "Invalid refresh token.". On RefreshTokenDatabaseError -> 503.
3. _get_user_status(user_id). On psycopg.Error -> revoke_family_by_raw_token(new_raw) then 503 (do not leave new_raw active).
4. If db_status != "active" -> revoke_family_by_raw_token(new_raw) then 401 "Invalid refresh token.".
5. create_access_token(user_id). On RuntimeError -> revoke_family_by_raw_token(new_raw) then 503.
6. Set new refresh cookie (same attributes).
7. Return TokenResponse.

POST /auth/logout
Purpose: revoke the refresh family and clear the cookie.
Flow:
1. If refresh_token cookie present -> revoke_family_by_raw_token(refresh_token). On RefreshTokenDatabaseError -> 503 (do not mask DB failure as success).
2. response.delete_cookie("refresh_token", path="/auth", secure=True, httponly=True, samesite="strict").
3. Return {"status": "logged out"} (always 200 unless DB failure on revocation).

Cookie configuration (constants):
python
_REFRESH_COOKIE_NAME = "refresh_token"
_REFRESH_COOKIE_PATH = "/auth"
_REFRESH_COOKIE_MAX_AGE = settings.REFRESH_TTL_DAYS * 86400  # 604800 (7 days)

_set_refresh_cookie(response, raw_token) helper sets all attributes.
_clear_refresh_cookie(response) helper deletes with the same attributes (verified Starlette 1.10.0 delete_cookie accepts secure, httponly, samesite).

Argon2id verifier (module level):
python
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)
_DUMMY_PASSWORD_HASH = _hasher.hash("dummy-password-for-timing-equalization")

_verify_password(password_hash, plain_password):
- Returns False if password_hash is None or empty.
- Catches VerifyMismatchError, VerificationError, InvalidHashError -> returns False.
- Never raises 500 on malformed hash.

_get_user_status(user_id):
- Opens get_auth_connection().
- SELECT auth_session.get_user_status(%s::uuid).
- Closes connection in finally.
- Returns None if row is None.
- May raise psycopg.Error (caller decides).

Exception mapping (auth routes):
- RefreshTokenError (ValueError) -> 401 (business validation: unknown, expired, revoked, reused).
- RefreshTokenDatabaseError (RuntimeError) -> 503 (infrastructure).
- psycopg.Error on login/refresh -> 503.
- RuntimeError on Vault -> 503.
- Generic 401 on any credentials failure.
- Logging: no token, no hash, no secret. Only "login: authenticate() failed", "refresh: rotate_refresh_token failed", etc.

18.6 NEW in v13 — API surface verification
Verified 12 November 2026 via:

powershell
docker exec securebiz-api python -c "import json, urllib.request; data = json.loads(urllib.request.urlopen('http://localhost:8000/openapi.json', timeout=10).read()); print('Total paths:', len(data['paths']))"

Result: Total paths: 8
- /
- /health
- /users
- /organizations/me
- /roles
- /auth/login
- /auth/refresh
- /auth/logout

19. AUTH DEPENDENCIES — NEW IN v13
19.1 Existing get_tenant_context — unchanged

File: app/api/dependencies.py (lines 58-150, unchanged since v12).

Uses debug headers X-Debug-User-Id and X-Debug-Org-Id.
APP_ENV guard (rejects production).
DEBUG_HEADERS_ENABLED guard (rejects when false).
sign_context + securebiz_install_context + yield + cleanup + commit/rollback + close.
Exception mapping: HTTPException -> rollback + propagate; Exception -> rollback + 500.

This function is STILL USED by /users, /organizations/me, /roles (Priority 6 migration pending).

19.2 NEW in v13 — UserContext dataclass

python
@dataclass(frozen=True)
class UserContext:
    user_id: str
    jti: str

Purpose: carry the authenticated user identity from get_current_user to get_authenticated_tenant_context. Frozen to prevent accidental mutation.

19.3 NEW in v13 — get_current_user()

python
def get_current_user(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> UserContext:

Behavior:
1. If no Authorization header or not starting with "Bearer " -> 401 "Authentication required.".
2. Extract token after "Bearer ". Empty -> 401 "Authentication required.".
3. verify_access_token(token).
4. On TokenValidationError -> logger.warning("get_current_user: token rejected") then 401 "Invalid or expired token.".
5. On RuntimeError (Vault unreachable) -> logger.error("get_current_user: JWT secret unavailable") then 503 "Authentication service unavailable.".
6. On any other Exception -> logger.error("get_current_user: unexpected internal error") then 500 "Internal error.".
7. Return UserContext(user_id=claims["sub"], jti=claims["jti"]).

Exception mapping:
- TokenValidationError -> 401 (invalid, expired, wrong alg, wrong iss/aud, missing claim, etc.).
- RuntimeError -> 503 (Vault only).
- Any other Exception -> 500 (never 503, never 401). A programming bug is not an infrastructure failure.

Logging: no token, no secret, no user_id, no jti. Only the class of failure.

19.4 NEW in v13 — get_authenticated_tenant_context()

python
def get_authenticated_tenant_context(
    user: UserContext = Depends(get_current_user),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
) -> Generator[Connection, None, None]:

Behavior:
1. If no X-Organization-Id header -> 400 "Header X-Organization-Id is required.".
2. _parse_uuid(x_organization_id, "X-Organization-Id") -> canonical org_id (invalid -> 422).
3. user_id = user.user_id.
4. Step 1: sign context.
   try: payload_json, sig_bytes, vault_version, key_version = sign_context(user_id, org_id)
   except ValueError -> logger.error("...invalid input") then 500 "Internal error."
   except RuntimeError -> logger.error("...Vault unavailable") then 503 "Context signing service unavailable."
   except Exception -> logger.error("...unexpected") then 500 "Internal error."
5. Step 2: open connection inside try.
   conn: Connection | None = None
   try:
       conn = get_raw_connection()
       ...
   finally: if conn is not None and not conn.closed: conn.close()
6. Step 3: install context.
   SELECT auth_security.securebiz_install_context(%s, %s, %s) with (payload_json, sig_bytes, "securebiz-context").
   If row is None or row[0] is not True -> RuntimeError("install_context did not return True").
7. Step 4: yield conn to route.
8. Step 5: success path: SELECT auth_security.securebiz_cleanup_context(); conn.commit().
9. Exception mapping:
   - except HTTPException: rollback (if conn not closed), raise.
   - except psycopg.OperationalError: rollback, logger.error("...database unavailable"), 503 "Data service unavailable.".
   - except psycopg.Error as exc: rollback, msg = exc.diag.message_primary if exc.diag else None.
       - if msg in _REFUSAL_MESSAGES_403: logger.warning, 403 "Access denied."
       - if msg in _TRANSIENT_MESSAGES_503: logger.warning, 503 "Context service unavailable."
       - else: logger.error("...unexpected SQL error"), 500 "Internal error."
   - except Exception: rollback, logger.error("...unexpected internal error"), 500 "Internal error.".

Classification constants (module-level, after logger):
python
_REFUSAL_MESSAGES_403 = frozenset({
    "Inactive or unauthorized user membership",
})
_TRANSIENT_MESSAGES_503 = frozenset({
    "Token expired",
    "Unknown or revoked signing key",
})

Rationale for the mapping:
- Inactive or unauthorized user membership -> 403 (identity known, membership refused).
- Token expired -> 503 (signed context expired before installation; retry with a fresh context may succeed; do NOT reuse the expired payload).
- Unknown or revoked signing key -> 503 (cryptographic key availability/configuration).
- Token replay detected -> 500 (context-JTI replay is an internal anomaly, not a direct client attack).
- Invalid Ed25519 signature -> 500 (internal crypto failure, not client auth failure).
- psycopg.OperationalError -> 503 (DB unavailable).
- All others -> 500 (unexpected contract violation).

Logging: no exception raw content. Only messages like "Authenticated tenant context: access refused" without exc, without payload, without signature.

Status: implemented and compiled. NOT YET USED by any route (Priority 6 migration pending).

19.5 Transaction lifecycle of get_authenticated_tenant_context
Success path:
get_raw_connection() -> install_context -> yield -> cleanup_context -> COMMIT -> CLOSE

Error path (any exception after connection opened):
ROLLBACK -> CLOSE

Do NOT call cleanup_context() after a rollback (the transaction context is already gone).

19.6 Invariant preserved
The single-transaction invariant is respected:
- install_context and cleanup_context share the same transaction.
- On success: cleanup then commit.
- On any exception: rollback (destroys context) then close.
- Never cleanup after rollback.

20. app/core/database.py
Unchanged from v12.

python
"""
app/core/database.py
================================================================================
SecureBiz Lab - PostgreSQL Connection Management
================================================================================
...
================================================================================
"""

import psycopg
from psycopg import Connection
from app.core.config import settings

def _connect(user, password) -> Connection:
    return psycopg.connect(
        host=settings.DB_HOST, port=settings.DB_PORT, dbname=settings.DB_NAME,
        user=user, password=password, connect_timeout=3,
    )

def get_raw_connection() -> Connection:  # securebiz_app
def get_auth_connection() -> Connection:  # securebiz_auth
def get_database_connection() -> Connection:  # alias for get_raw_connection
@contextmanager
def get_database_session() -> Generator[Connection, None, None]:  # business role, auto-commit/rollback

Verified by TCP test: get_auth_connection() successfully connects as securebiz_auth from the API container.

21. AUTHENTICATION AND PROVISIONING — STATUS AFTER PRIORITY 5
21.1 What is implemented and verified (Priority 5 CLOSE)

Element	Status
app/core/vault.py get_jwt_secret()	Verified (32 bytes, kid=v2, no rotation)
Vault KV secret secret/data/securebiz/jwt	Present (version 3, never displayed)
app/core/jwt.py create_access_token	Verified (HS256, kid, claims)
app/core/jwt.py verify_access_token	Verified (18/18 tests, alg/iss/aud/exp/iat/sub/jti/token_type)
app/services/refresh.py	Rewritten (advisory locks, RefreshTokenError, RefreshTokenDatabaseError, revoke_family_by_raw_token)
app/schemas/auth.py	Created (LoginRequest with EmailStr, TokenResponse)
app/api/routes/auth.py	Created (/auth/login, /auth/refresh, /auth/logout)
app/api/dependencies.py	Extended (UserContext, get_current_user, get_authenticated_tenant_context)
app/main.py	auth_router registered (8 paths verified)
requirements.txt	PyJWT==2.10.1, argon2-cffi==25.1.0, email-validator==2.2.0 added
Packages in running container	PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1, httpx2 2.16.0
Packages persisted in image	NO (rebuild pending — critical debt)
auth_private.credentials	1 row (test credential, Argon2id)
auth_session.refresh_tokens	0 rows (clean)
auth_session active_tokens	0
public.users	1 row (status = active)
Priority 5 tests	P1-P8 (8/8) + P11 (1/1) all passed

21.2 What is NOT implemented (Priority 6 and beyond)

Element	Status
Migration of /users, /organizations/me, /roles to get_authenticated_tenant_context	Pending — Priority 6
Removal of X-Debug-* headers from get_tenant_context	Pending — Priority 6
tests/test_isolation.py migration to JWT	Pending — Priority 6 or 9
Provisioning endpoint / script for Argon2id hashes	Pending — dette v13
state_check.py extension for auth_session.refresh_tokens and get_user_status	Pending — Priority 9
Rebuild of securebiz-lab-api:latest image	Pending — critical debt (Priority 7)
Runtime tenant-isolation tests under JWT	Pending — Priority 9

21.3 Provisioning searches already performed
Repository-wide searches for INSERT INTO users, INSERT INTO memberships, create_user, create_membership, provision_user, seed_user, seed_data, create_organization returned nothing. Migration inspection confirmed no user/organization/membership provisioning routine. Git history confirmed no committed INSERT statement.

New in v13: only the auth_private.credentials table has been manually populated (1 row), via psql as securebiz_user, for the test user a2c643f2-7212-4693-bc7f-d220cb9cdaf4. This is a test credential, not a provisioning mechanism.

21.4 Authentication database role
securebiz_auth has:

USAGE on auth_private;
no direct table privilege on credentials;
EXECUTE on authenticate;
USAGE on auth_session;
SELECT, INSERT, UPDATE on auth_session.refresh_tokens;
no DELETE on auth_session.refresh_tokens (revocation is by UPDATE revoked_at);
EXECUTE on auth_session.get_user_status;
no parent-role membership.

Prior connection attempt without a password failed with fe_sendauth: no password supplied. This does not prove the role is invalid.

TCP connection from the API container to securebiz_auth was successful (verified ('securebiz_auth',)).

22. PASSWORD HASHING AND JWT — DECISIONS IMPLEMENTED IN v13
22.1 Password hashing — IMPLEMENTED

Library: argon2-cffi==25.1.0
Parameters:
python
PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)

Compatibility: container Python 3.12.16; argon2-cffi 25.1.0 officially supports Python 3.12 through 3.14.

Implemented in app/api/routes/auth.py as _hasher. Only verify() is used in auth.py. Hash generation (for provisioning) is manual/offline.

Dummy hash _DUMMY_PASSWORD_HASH = _hasher.hash("dummy-password-for-timing-equalization") is computed at import time and used in login() when the email is unknown, to prevent timing-based enumeration.

Provisioning: the only credential in the database was created manually via psql as securebiz_user, using the same PasswordHasher parameters and printing only the hash (never the plaintext). A provisioning endpoint or script is Pending (Priority 8).

Separation preserved:
- Argon2id hashing and verification in the application.
- Password hashes stored in auth_private.credentials.
- Restricted retrieval through auth_private.authenticate(...).
- No direct credentials-table SELECT for securebiz_auth.

22.2 JWT — IMPLEMENTED
Decision	Choice
Algorithm	HS256
Library	PyJWT 2.10.1
Secret storage	Vault KV secret/data/securebiz/jwt (Vault KV-v2)
Secret retrieval	get_jwt_secret() in app/core/vault.py
Current kid	v2 (cosmetic; actual Vault version 3 due to a double rotation)
Access token lifetime	900 seconds (15 minutes) via settings.JWT_ACCESS_TTL_SECONDS
iss	securebiz-api
aud	securebiz-api
Claims	sub (user UUID), iss, aud, iat, exp, jti (UUID4), token_type="access"
kid in header	Yes

create_access_token(user_id):
- Validates user_id is a canonical UUID string (lowercase 8-4-4-4-12).
- Calls get_jwt_secret() -> (current_secret, current_kid, _, _).
- Encodes HS256 with headers={"kid": current_kid}.
- Returns str.

verify_access_token(token):
- Rejects empty token.
- Loads current and previous keys from get_jwt_secret().
- Reads unverified header, checks alg == "HS256" (defense in depth), extracts kid, verifies kid is in {current_kid, previous_kid}.
- jwt.decode with algorithms=["HS256"], audience=settings.JWT_AUDIENCE, issuer=settings.JWT_ISSUER, leeway=30s.
- Requires: sub, iss, aud, iat, exp, jti, token_type.
- Manual checks: token_type == "access"; sub is canonical UUID; jti is canonical UUID; iat and exp are int; exp > iat; iat not in future (with 30s leeway).
- Returns claims dict.
- All failures raise TokenValidationError (ValueError subclass) with generic messages (no token, no secret, no raw PyJWT content).

Why HS256 and not RS256/ES256: the API is the only issuer and verifier. No federation. HS256 is standard for this case. If the lab becomes multi-service, migration to RS256/ES256 will be needed.

Why Vault KV for the secret and not .env: centralized secret management, audit, rotation, consistency with existing Vault usage for Transit.

22.3 Refresh token — IMPLEMENTED
Decision	Choice
Format	secrets.token_urlsafe(32) (256 bits)
Storage	SHA-256 hash (32 bytes) in auth_session.refresh_tokens.token_hash (BYTEA, CHECK octet_length = 32)
Lifetime	7 days (settings.REFRESH_TTL_DAYS * 1 day via make_interval(days => %s))
Transport	Cookie refresh_token: HttpOnly, Secure, SameSite=Strict, Path=/auth, Max-Age=604800
Rotation	On every use. Old row revoked (revoked_at), new row inserted, old.replaced_by = new.id
Reuse detection	Yes. If revoked_at is not null on the provided token -> revoke entire family, COMMIT before raise
family_id	UUID shared across rotations of the same login session
Bulk revocation	On reuse detection. Also available via revoke_family(family_id) and revoke_family_by_raw_token(raw)

Concurrency (verified v13):
python
_acquire_family_lock(cur, family_id):
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(family_id),))

All three functions (rotate_refresh_token, revoke_family, revoke_family_by_raw_token) acquire the family advisory lock BEFORE any row lock. This uniform lock order (family -> row) prevents the deadlock that would arise from the opposite order.

rotate_refresh_token flow:
1. SELECT family_id FROM auth_session.refresh_tokens WHERE token_hash = %s (no lock).
   If None -> RefreshTokenError("unknown token").
2. _acquire_family_lock(cur, family_id).
3. SELECT id, user_id, family_id, revoked_at, (expires_at <= clock_timestamp()) AS is_expired FROM ... WHERE token_hash = %s FOR UPDATE.
   If None -> RefreshTokenError("invalid token state").
   If locked_family_id != family_id -> RefreshTokenError("invalid token state").
4. If revoked_at is not None -> revoke entire family, COMMIT, raise RefreshTokenError("reuse detected").
5. If is_expired -> RefreshTokenError("expired").
6. Generate new_raw, insert new row (RETURNING id), update old row (revoked_at, replaced_by = new.id). COMMIT. Return (new_raw, user_id).

revoke_family(family_id) flow:
1. _acquire_family_lock(cur, family_id).
2. UPDATE auth_session.refresh_tokens SET revoked_at = clock_timestamp() WHERE family_id = %s AND revoked_at IS NULL.
3. COMMIT.
Idempotent. No exception on missing family.

revoke_family_by_raw_token(raw_token) flow:
1. If raw_token is not str or empty -> return (silent no-op).
2. token_hash = SHA-256(raw_token).
3. SELECT family_id FROM auth_session.refresh_tokens WHERE token_hash = %s (no lock).
   If None -> conn.rollback(); return (silent no-op).
4. _acquire_family_lock(cur, family_id).
5. UPDATE ... SET revoked_at = clock_timestamp() WHERE family_id = %s AND revoked_at IS NULL.
6. COMMIT.
Idempotent. Unknown token -> silent no-op. Used by /auth/logout.

Exception separation:
- RefreshTokenError (ValueError): business validation (unknown token, expired, reuse detected, invalid state). Mapped to 401.
- RefreshTokenDatabaseError (RuntimeError): database failure. Deliberately does NOT inherit from RefreshTokenError, so a caller's except RefreshTokenError cannot swallow a DB failure. Mapped to 503.

Both inherit from different bases on purpose. This separation was introduced in Priority 5 (Bloc B1bis).

23. TESTING AND VALIDATION — PRIORITY 5 CLOSE
23.1 Priority 5 functional tests — executed 12 November 2026

Bloc E2 v7 (P1-P8) — run ac649048:
Test	Result
P1 login OK	200 + access_token + refresh cookie
P2 unknown email	401 "Invalid credentials."
P3 wrong password	401 "Invalid credentials."
P4 refresh rotation	200 + new cookie, SAME family_id (verified via SQL)
P5 replay (old cookie)	401 + F1 fully revoked (verified via SQL: count(*) WHERE revoked_at IS NULL = 0)
P6 new login	200 + F2 distinct from F1
P7 logout	200 + F2 revoked
P8 logout without cookie	200
F1/F2 SQL revocation	active=0 for both families, total=3 rows
Active tokens (all users)	0 after cleanup

Bloc E2 bis v4 (P11) — run 89fe8258:
Test	Result
P11 login (F3)	200 + cookie
P11 disable user (UPDATE users SET status='disabled')	verified SELECT status='disabled'
P11 refresh with disabled user	401
P11 F3 revoked	0 active rows in F3
P11 user reactivated (finally)	verified SELECT status='active'
Final state	credentials=1 refresh_tokens=0 active_tokens=0 user=active

23.2 Historical results (from v12)
Check	Historical result
pytest	3/3 passed
Bandit 1.9.4	0 findings
pip-audit 2.10.1	no known vulnerabilities at the time
scripts/state_check.py	4 OK, 6 skipped

scripts/state_check.py performs an end-to-end install_context + get_context test with rollback, but does not call get_user_status or the three administrative functions.

23.3 Test files
Bloc C — jwt.py unit tests: 18/18 passed (P1-P3 + N1-N15). Covered: valid token, wrong algorithm (none, RS256), wrong kid, wrong iss/aud, expired, wrong token_type, non-canonical sub/jti, missing required claim, tampered signature, create with non-canonical UUID.

Bloc E2 v7 — refresh endpoints: 8/8 passed. See §23.1.

Bloc E2 bis v4 — disabled user: 1/1 passed. See §23.1.

23.4 Not yet tested
- JWT via Authorization: Bearer (only the cookie header was used for replay tests)
- get_authenticated_tenant_context (implemented but not called by any route)
- Tenant isolation under JWT (tests/test_isolation.py still uses debug headers)
- Full transaction lifecycle edge cases (cleanup failure, commit failure, etc.)
- state_check.py extended coverage (auth_session.refresh_tokens, get_user_status, credentials)

24. CONSOLIDATED SECURITY ASSESSMENT
24.1 Positive findings — v12 base + v13 additions

v12 findings (unchanged):
- securebiz_app is non-superuser and has no BYPASSRLS.
- securebiz_auth is non-superuser and has no BYPASSRLS.
- securebiz_owner is NOLOGIN, non-superuser and has no BYPASSRLS.
- No role memberships involving the four inspected roles were returned.
- The dedicated membership query for securebiz_auth returned zero rows.
- securebiz_app cannot use auth_private.
- securebiz_auth cannot use auth_security.
- securebiz_auth has no direct credentials-table privilege.
- securebiz_auth can execute auth_private.authenticate(...).
- securebiz_owner has SELECT on credentials.
- Six tenant-sensitive public IAM tables have RLS and FORCE RLS enabled.
- The API uses securebiz_app as its business database role.
- pgsodium 3.1.9 is installed in the custom PostgreSQL image.
- The dependency defaults DEBUG_HEADERS to false.
- The dependency rejects requests when APP_ENV=production.
- The dependency installs and cleans up signed context within a single connection lifecycle.
- The database context installation function verifies active user, membership and organization before context installation.
- The live RLS inspection returned 22 policies across six tenant-sensitive public IAM tables.
- Application policies use tenant-context conditions.
- Several application policies explicitly invoke RBAC permission checks.
- Role and role-permission policies contain system-role restrictions.
- The five critical security functions have been inspected individually.
- The trigger protecting system roles has been identified and inspected.
- The explicit static routine search for writes to public.roles returned zero rows.
- The global SECURITY DEFINER inventory is completed (33 pre-002, 34 post-002).
- Twenty-five SECURITY DEFINER routines belong to pgsodium (out of scope, not modified).
- All nine application SECURITY DEFINER routines are owned by securebiz_owner with search_path=pg_catalog, pg_temp.
- Effective EXECUTE privileges were verified for all eight pre-v12 application SECURITY DEFINER routines.
- securebiz_app can execute the context installation, context retrieval, context cleanup and permission-checking functions.
- securebiz_auth can execute the authentication lookup function but cannot directly access the credentials table.
- The purge and public-key administration functions are executable only by securebiz_owner among the three inspected application/owner roles.
- No RESTRICTIVE policy exists (0 rows).
- No policy is assigned to PUBLIC or unexpected roles (0 rows).
- No application default privilege exists.
- The three read-only API routes respect the dependency contract.
- securebiz_get_context is invoked by 20 RLS policies in the migration.
- scripts/state_check.py performs an end-to-end install-context test with rollback.
- scripts/state_check.py skips structural checks when admin credentials are absent.
- securebiz_register_public_key validates kid non-empty and Ed25519 key = 32 bytes.
- securebiz_revoke_public_key is idempotent and preserves revoked_at.
- securebiz_purge_expired_security_data applies an explicit ten-minute margin before deletion.

v12 additions (unchanged):
- Migration 002 applied successfully with ON_ERROR_STOP=1.
- auth_session schema created, owned by securebiz_user.
- auth_session.refresh_tokens created, owned by securebiz_user, with 3 constraints and 3 indexes.
- auth_session.get_user_status(UUID) created, owned by securebiz_owner, SECURITY DEFINER, search_path=pg_catalog, pg_temp.
- securebiz_auth has SELECT, INSERT, UPDATE on auth_session.refresh_tokens.
- securebiz_auth has EXECUTE on auth_session.get_user_status.
- securebiz_app has no privilege on auth_session.refresh_tokens or auth_session.get_user_status.
- PUBLIC has no privilege on auth_session.refresh_tokens or auth_session.get_user_status.
- securebiz_owner has USAGE on auth_session and SELECT on auth_session.refresh_tokens.
- get_auth_connection() implemented in app/core/database.py.
- AUTH_DB_USER / AUTH_DB_PASSWORD in config.py, docker-compose.yml, .env.
- VAULT_DEV_ROOT_TOKEN corrected in .env.
- TCP connection as securebiz_auth from the API container verified.
- API starts successfully with Application startup complete.
- Vault Ed25519 key securebiz-context already exists (no recreation).

v13 additions (new):
- JWT HS256 issuance verified (18/18 tests): only HS256 accepted, alg header verified, kid verified against current and previous.
- JWT verification rejects: alg=none, alg=RS256, wrong kid, wrong iss, wrong aud, expired, wrong token_type, non-canonical sub/jti, missing required claim, tampered signature, create with non-canonical UUID.
- Refresh token rotation verified (P4): same family_id, new cookie, new JWT.
- Reuse detection verified (P5): old cookie -> 401 + entire family F1 revoked (including the replacement token).
- Logout verified (P7): family F2 revoked, cookie cleared.
- Logout idempotent (P8): 200 without cookie.
- Disabled user (P11): refresh -> 401 + F3 revoked.
- No orphan tokens after 9 tests: active_tokens = 0 in whole DB.
- Argon2id dummy hash prevents timing-based user enumeration.
- Generic 401 on all credentials failures (no distinction between unknown email and wrong password).
- get_current_user exception mapping: 401 (invalid), 503 (Vault), 500 (programming error). No bug masked as 503.
- get_authenticated_tenant_context exception mapping: 401 (auth), 403 (membership refusal), 500 (SQL anomaly), 503 (OperationalError). No refusal masked as unavailability.
- Advisory lock on family_id: uniform order (family -> row) across rotate/revoke/revoke_by_raw. Prevents deadlock.
- RefreshTokenError (ValueError) and RefreshTokenDatabaseError (RuntimeError) are strictly separated. except RefreshTokenError cannot swallow a DB failure.
- RefreshTokenError mapped to 401, RefreshTokenDatabaseError mapped to 503.
- All 22 RLS policies remain untouched during Priority 5.
- All 8 SQL functions unchanged during Priority 5.
- All migrations unchanged during Priority 5.

24.2 Findings requiring further review — v12 base + v13 additions

v12 findings (unchanged):
- Every table is owned by superuser securebiz_user.
- securebiz_owner is not the table owner.
- securebiz_owner has no BYPASSRLS.
- Six owner policies permit all-row access for the effective securebiz_owner role.
- securebiz_app has direct DML privileges on several IAM tables.
- public.permissions is not RLS-enabled.
- Authentication and security tables are not RLS-enabled (intentional; protected by ACLs and functions).
- The global SECURITY DEFINER inventory is complete, but the full security review of every routine is not.
- Twenty-five pgsodium routines require contextual interpretation.
- authenticate does not verify passwords or issue JWTs.
- The debug-header dependency accepts client-supplied debug identity headers when debug mode is enabled outside exact production.
- The debug-header dependency does not validate JWTs.
- A debug header's UUID syntax check is not authentication.
- The current user and membership provisioning origin remains unknown as a versioned artifact (manually provisioned with hardcoded test identities is the inferred origin).
- Password hashing is not established as a provisioning workflow (only a manual test credential).
- Vault is configured in development mode with a development root token.
- Startup calls Vault key initialization.
- The transaction lifecycle has not been exhaustively tested.
- The trigger's current_user condition must be evaluated against SECURITY DEFINER execution paths.
- The zero-row static role-write search does not exclude dynamic SQL or indirect writes.
- The administrative caller for public-key registration and revocation has not been identified.
- The operational caller for expired security-data cleanup has not been identified.
- The function EXECUTE ACLs do not prove the absence of indirect privilege-escalation paths.
- The effect of owner policies on each SECURITY DEFINER routine must be evaluated.
- The cleanup function's transaction behavior has not been tested across all paths.
- scripts/state_check.py contains hardcoded TEST_USER_ID, TEST_ORG_ID, EXPECTED_PUBKEY_HEX.
- EXPECTED_PUBKEY_HEX is coupled to the Vault -dev mode.
- No test exercises the pre-v12 SECURITY DEFINER functions directly.
- scripts/state_check.py duplicates Vault signing logic.
- The debug-header guard rejects only the exact value production.
- Tenant lifecycle tests are not automated.
- Tenant isolation under securebiz_app and a signed context is not dynamically tested.
- securebiz_get_context is VOLATILE, not STABLE.
- auth_session.refresh_tokens has RLS disabled (intentional).
- securebiz_auth has SELECT, INSERT, UPDATE on refresh_tokens but no DELETE.

v13 additions (new):
- Rebuild of securebiz-lab-api:latest is PENDING. Priority 5 packages are in the running container but not in the image. Any container restart loses them. CRITICAL.
- httpx.ASGITransport does not inject cookies set via cookies.set(). Tests must use explicit Cookie header for replay scenarios.
- TestClient of Starlette 1.10.0 requires httpx2 (separate package from httpx). Both httpx and httpx2 have the cookie limitation.
- $LASTEXITCODE is unreliable for psql and docker cp when stderr is written. Verify DB state or file existence instead.
- $ErrorActionPreference = "Stop" stops PowerShell scripts on native stderr. Use local Continue + try/finally.
- users_status_check allows only 'active', 'disabled', 'pending'. 'inactive' is rejected.
- get_authenticated_tenant_context is implemented and compiled but NOT YET USED by any route.
- get_tenant_context (debug headers) is STILL USED by /users, /organizations/me, /roles.
- tests/test_isolation.py still uses debug headers.
- auth_private.credentials contains 1 test row, created manually, not by a provisioning workflow.
- state_check.py does not yet cover auth_session.refresh_tokens, get_user_status, or credentials.
- Priority 5 changes (9 files) have not been committed to git yet.
- The API image builds can fail on PyPI timeout (observed twice on 12 November 2026). Mitigation: increase pip timeout/retries in Dockerfile, or use a PyPI mirror, or verify Docker MTU.

25. CURRENT INVESTIGATION STATUS
Investigation	Actual status

v12 base (unchanged):
Repository inventory	Completed
Docker Compose inspection	Completed
PostgreSQL Dockerfile inspection	Completed
Safe environment-variable name inspection	Completed
PostgreSQL role attributes	Completed
Role membership inspection for the four roles	Completed
Dedicated securebiz_auth membership inspection	Completed — 0 rows
Schema ACL inspection	Completed
Table ownership and ACL inspection	Completed — 111 rows (pre-002)
Direct securebiz_owner table privileges	Completed
Direct securebiz_auth credentials privileges	Completed
Default privileges inspection	Completed — 5 rows, all pgsodium
RLS enabled/FORCE RLS flags	Completed
Live RLS policy inspection	Completed — 22 policies
Absence of RESTRICTIVE policies	Completed — 0 rows
Absence of PUBLIC-assigned policies	Completed — 0 rows
Five critical function inspections	Completed
Four additional security function inspections	Completed with full definitions
Global SECURITY DEFINER inventory	Completed — 33 routines (pre-002) / 34 (post-002)
Effective EXECUTE privileges for eight application functions	Completed
Trigger inspection	Completed
Static search for explicit writes to roles	Completed — 0 rows
app/main.py inspection	Completed
app/api/dependencies.py inspection	Completed
app/core/database.py inspection	Completed
Call-site inventory of the six security functions	Completed
Administrative invocation mapping	Completed
Dependency contract in routes	Completed — respected
Test identity and public key hardcoded in state_check.py	Completed — documented
Migration 002 (auth_session schema)	Completed
get_user_status function inspection	Completed
Effective privileges on auth_session objects	Completed
get_auth_connection() implementation	Completed
AUTH_DB_* configuration	Completed
TCP connection as securebiz_auth	Completed — verified
API startup with new config	Completed

v13 additions (new):
app/core/vault.py get_jwt_secret()	Completed — verified (32 bytes, kid=v2, no rotation)
Vault KV secret secret/data/securebiz/jwt	Completed — present (version 3, never displayed)
app/core/jwt.py create_access_token + verify_access_token	Completed — 18/18 tests passed
app/services/refresh.py rewrite (advisory locks)	Completed
RefreshTokenError / RefreshTokenDatabaseError separation	Completed
app/schemas/auth.py	Completed
app/api/routes/auth.py	Completed
app/api/dependencies.py UserContext / get_current_user / get_authenticated_tenant_context	Completed
app/main.py auth_router registration	Completed — 8 paths verified
Priority 5 functional tests P1-P8	Completed — 8/8 passed (run ac649048)
Priority 5 functional test P11	Completed — 1/1 passed (run 89fe8258)
DB state after Priority 5	Verified — credentials=1, refresh_tokens=0, active_tokens=0, user=active
Stale files cleanup	Completed — none remain
Rebuild of securebiz-lab-api:latest	PENDING — critical debt
git commit / push of Priority 5 changes	PENDING
Migration of IAM routes to get_authenticated_tenant_context	PENDING — Priority 6
Debug-header removal from get_tenant_context	PENDING — Priority 6
tests/test_isolation.py migration to JWT	PENDING — Priority 6 or 9
Provisioning endpoint for Argon2id hashes	PENDING — Priority 8
state_check.py extension (auth_session, get_user_status, credentials)	PENDING — Priority 9
Runtime tenant-isolation tests under JWT	PENDING — Priority 9
Full transaction lifecycle tests	PENDING — Priority 9

26. NEXT PRIORITIES
The following priorities are ordered by dependency. Priority 6 cannot start before the rebuild (Priority 7) is validated, because the container restart would lose the Priority 5 packages and crash the API. Priority 7 must therefore be treated as a prerequisite, even if numbered separately.

Priority 6 — Migrate IAM routes to get_authenticated_tenant_context

Objective: replace get_tenant_context (debug headers) with get_authenticated_tenant_context (JWT + X-Organization-Id) on the three IAM routes.

Files to modify:
- app/api/routes/users.py
- app/api/routes/organizations.py
- app/api/routes/roles.py

Steps:
1. In each file, change:
   from app.api.dependencies import get_tenant_context
   to:
   from app.api.dependencies import get_authenticated_tenant_context
2. In each route, change:
   Depends(get_tenant_context)
   to:
   Depends(get_authenticated_tenant_context)
3. Update tests/test_isolation.py:
   - Obtain a JWT via POST /auth/login with test-user@test.com / TestPassword!2026.
   - Send Authorization: Bearer <jwt>.
   - Send X-Organization-Id: 1a40e607-b991-4b06-ad1f-13106d65b12a instead of X-Debug-Org-Id.
   - Remove X-Debug-User-Id.
4. Verify /users, /organizations/me, /roles return the expected data with a valid JWT and the correct X-Organization-Id.
5. Verify the routes return 401 without a JWT.
6. Verify the routes return 400 without X-Organization-Id.
7. Verify a JWT for a user without an active membership in X-Organization-Id returns 403 (from the SQL refusal "Inactive or unauthorized user membership").
8. Do NOT remove get_tenant_context yet. It stays in dependencies.py for backward compatibility (some internal tests may still use it).

Test user: test-user@test.com / TestPassword!2026 (test credential only). The credential is in auth_private.credentials (1 row).

Important: after this migration, the /users, /organizations/me, /roles routes no longer accept X-Debug-* headers. Any caller relying on the debug path will break. This is intentional.

Priority 7 — Rebuild securebiz-lab-api:latest image (critical debt)

Objective: persist PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1, httpx2 2.16.0 in the image, so that any container restart keeps the API functional.

Observed problem: docker compose build api fails on PyPI timeout (ReadTimeoutError on files.pythonhosted.org). Two occurrences on 12 November 2026. The network is reachable (python:3.12-slim pull succeeds), so the issue is intermittent slowness on the CDN.

Corrective options (in order of preference):

Option 1 (recommended) — increase pip timeout and retries in Dockerfile:
Modify the Dockerfile line 9 from:
    RUN pip install --no-cache-dir -r requirements.txt
to:
    RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

Option 2 — Use a PyPI mirror:
    RUN pip install --no-cache-dir --timeout 120 --retries 5 \
        -i https://mirrors.aliyun.com/pypi/simple/ \
        --trusted-host mirrors.aliyun.com \
        -r requirements.txt

Option 3 — If both fail with TLS timeouts, inspect Docker MTU. Run:
    docker run --rm --network host python:3.12-slim python -c "import urllib.request as u; print(len(u.urlopen('https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-50.0.2.tar.gz', timeout=30).read()))"
If --network host works but the default bridge does not, add "mtu": 1400 to Docker Desktop daemon.json.

After successful build:
1. docker compose up -d --force-recreate api
2. Wait 5 seconds.
3. Verify docker ps shows securebiz-api Up.
4. Verify /openapi.json returns Total paths: 8.
5. Verify inside the container:
   - PyJWT 2.10.1
   - argon2-cffi 25.1.0
   - email-validator 2.2.0
   - httpx 0.28.1

Note: httpx2 is only needed for TestClient. If future tests use httpx.AsyncClient directly, httpx2 is not strictly required. Currently, TestClient still imports it, so include it in requirements.txt for compatibility.

Priority 8 — Provisioning endpoint or script for Argon2id hashes

Objective: create a controlled way to provision new users with Argon2id password hashes.

Constraints:
- Hash must use the same parameters as auth.py (PasswordHasher with time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16).
- Insert into auth_private.credentials (via securebiz_user or a dedicated provisioning role).
- Do NOT use securebiz_auth (no INSERT privilege on credentials).
- Audit log required (who created which user, when).
- Never log or return the hash.

Design decisions to make:
- Endpoint (POST /admin/users) or script (scripts/provision_user.py)?
- Who can invoke it? (No admin role defined yet.)
- How does the plaintext password reach the provisioner? (Manual entry, or generated, or SMTP invite flow?)

This is a non-trivial design. Defer to a dedicated priority once Priorities 6 and 7 are closed.

Priority 9 — Tests and state_check extension

- Unit tests for jwt.py: already covered in Bloc C (18/18).
- Unit tests for refresh.py: P1-P8 and P11 done manually, but not in tests/.
- Integration tests for /auth/*: manual only.
- Tenant isolation tests under JWT: pending (depends on Priority 6).
- Full transaction lifecycle tests: pending (cleanup failure, commit failure, rollback failure, connection close on each path).
- Extend scripts/state_check.py to check:
  - auth_session.refresh_tokens (table exists, count)
  - auth_session.get_user_status (EXECUTE ACL, behavior)
  - auth_private.credentials (count, no hash leaked)

27. KNOWN PITFALLS

v12 pitfalls (unchanged):
- Do not confuse a database authentication function with complete API authentication.
- Do not confuse a signed tenant context with user authentication.
- Do not trust client-supplied organization IDs.
- Do not assume a docstring proves authorization.
- Do not use securebiz_user as the runtime account.
- Do not grant BYPASSRLS to runtime roles.
- Do not assume initialization scripts rerun on an existing database.
- Do not assume the existing user was created manually as the only possible origin.
- Do not assume the password-hashing scheme is known (it is now known: Argon2id with specific parameters).
- Do not interpret fe_sendauth: no password supplied as proof that a database role is invalid.
- Do not accept HTTP 500 as proof of successful tenant isolation.
- Do not treat historical test results as current results.
- Do not split PowerShell control-flow blocks across separate submissions.
- Do not expose secrets while inspecting configuration.
- Do not assume SECURITY DEFINER automatically bypasses FORCE RLS.
- Do not assume securebiz_owner owns the inspected tables.
- Do not assume a grant to securebiz_user restricts a superuser.
- Do not infer function privileges from schema or table privileges.
- Do not infer the absence of PUBLIC privileges on every object from a table ACL query alone.
- Do not modify grants before inspecting application dependencies.
- Do not consider UUID parsing equivalent to authentication.
- Do not consider APP_ENV != production sufficient to prove debug mode is safe.
- Do not remove context cleanup or transaction binding during authentication implementation.
- Do not modify app/main.py during the current database function-security investigation.
- Do not rerun the completed 22-policy RLS inspection.
- Do not repeat the five critical function inspections without a specific reason.
- Do not interpret the zero-row role-write search as proof that no role-writing path exists.
- Do not treat the absence of a global SECURITY DEFINER inventory output in an earlier document as proof that the user never executed that query.
- Do not rerun the global SECURITY DEFINER inventory.
- Do not assume the 25 pgsodium routines are application-defined functions.
- Do not assume that a function being executable only by securebiz_owner proves that an administrative invocation mechanism exists.
- Do not grant public-key administration or purge functions to runtime roles without a dedicated security design.
- Do not treat function EXECUTE ACLs as a complete analysis of indirect execution paths.
- Do not assume that the current transaction cleanup has been exhaustively tested.
- Do not run the global SECURITY DEFINER inventory again as the next operation.
- Do not treat the hardcoded UUIDs in scripts/state_check.py as secrets.
- Do not rely on EXPECTED_PUBKEY_HEX after a Vault container recreation.
- Do not add a RESTRICTIVE policy without inspecting the existing PERMISSIVE model.
- Do not assume a route is safe merely because it uses with connection.cursor().
- Do not consider scripts/state_check.py a privileged provisioning script.
- Do not modify the default privileges of pgsodium or pgsodium_masks.
- Do not treat the absence of a caller for purge_expired_security_data as a bug.
- Do not assume app_has_permission joins public.permissions.
- Do not assume securebiz_get_context is STABLE.
- Do not use Add-Content to append to .env without ensuring a trailing newline.
- Do not use [Convert]::ToHexString() in PowerShell 5.1.
- Do not rely on Set-Clipboard in non-STA PowerShell.
- Do not confuse the Vault root token dev-only-root-token with a production token.
- Do not assume VAULT_DEV_ROOT_TOKEN will change on container recreation.
- Do not assume the Vault Ed25519 key will be recreated on container restart.
- auth_session.refresh_tokens has RLS disabled intentionally.
- securebiz_auth has SELECT, INSERT, UPDATE on refresh_tokens but no DELETE.
- get_user_status returns NULL for unknown users.
- get_user_status is VOLATILE, not STABLE.

v13 additions (new):
- Do not use client.cookies.set() with httpx.ASGITransport. Cookies are stored but not injected in subsequent requests. Use headers={"Cookie": f"refresh_token={token}"} for replay tests.
- Do not assume TestClient works out of the box. Starlette 1.10.0 TestClient requires httpx2, which is a separate package from httpx. Installing httpx2 is needed if TestClient is used.
- Do not check $LASTEXITCODE after docker exec psql UPDATE or docker cp. PowerShell sets it to 1 on stderr writes even on success. Verify the DB state (SELECT) or Test-Path instead.
- Do not run a script with $ErrorActionPreference = "Stop" if it calls docker exec / docker cp. Use local Continue + try/finally.
- Do not assume psql -t -A with RETURNING returns a single line. It returns the value plus INSERT 0 1. Parse with regex.
- Do not use 'inactive' for user status. users_status_check allows only 'active', 'disabled', 'pending'. Use 'disabled' to disable a user.
- Do not execute fragments of function Invoke-BlockX { ... }. Variables are undefined in global scope, throw runs without finally, state is silently corrupted. Always execute the entire block.
- Do not confuse docker compose build api with a config change. It reads Dockerfile and requirements.txt, builds an image. It does not modify docker-compose.yml, Dockerfile, requirements.txt, .env, containers, or volumes. But docker compose up -d --force-recreate api DOES recreate the API container.
- Do not assume PyPI timeouts are permanent. Retry docker compose build api. If persistent, increase --timeout and --retries in the Dockerfile, or use a mirror.
- Do not use RefreshTokenError for DB failures. RefreshTokenError is business validation (401). RefreshTokenDatabaseError is infrastructure (503). They inherit from different bases on purpose.
- Do not remove the advisory lock on family_id. It prevents concurrent rotation and revocation from corrupting the family. Order must be family first, then row, uniformly across rotate/revoke/revoke_by_raw.
- Do not call cleanup_context() after a rollback. The transaction context is already gone.
- Do not assume get_current_user maps all exceptions to 503. Only RuntimeError (Vault) maps to 503. Any other unexpected exception maps to 500. A programming bug is not an infrastructure failure.
- Do not assume get_authenticated_tenant_context maps all psycopg.Error to 503. Only psycopg.OperationalError maps to 503. Other psycopg.Error are classified by primary message: "Inactive or unauthorized user membership" -> 403, "Token expired" / "Unknown or revoked signing key" -> 503, all others -> 500. Token replay detected and Invalid Ed25519 signature map to 500, not 401.
- Do not log the token, the secret, the password hash, the user_id, or the jti in authentication logs. Only log the class of failure.
- Do not use cookies.set() to simulate replay. Use headers={"Cookie": f"refresh_token={token}"}.
- Do not commit Priority 5 changes before the rebuild is validated. The rebuild must be done first, then git add -A, git commit, git push.

28. EXACT CONTINUATION POINT — VERSION 13

Priority 5 is CLOSED. All 9 functional tests passed on 12 November 2026 (P1-P8 and P11).

Verified DB state (after tests and cleanup):
- auth_private.credentials : 1 row (test credential, Argon2id, test-user@test.com)
- auth_session.refresh_tokens : 0 rows
- auth_session active_tokens : 0
- public.users : 1 row (status = active)
- public.memberships : 1 row (active, user in org 1a40e607-b991-4b06-ad1f-13106d65b12a)

Verified API state:
- securebiz-api container: Up 2 hours (old image, no rebuild yet)
- /openapi.json: 8 paths (/ , /health, /users, /organizations/me, /roles, /auth/login, /auth/refresh, /auth/logout)
- Packages in running container: PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1, httpx2 2.16.0
- Packages in image: NONE of the above (image is v12 state)
- Stale files: none remain

The immediate next operation is the REBUILD of the API image (Priority 7). This is a prerequisite, not a follow-up. Any restart of the container without the rebuild will crash the API.

The rebuild has failed twice on 12 November 2026 (PyPI timeout). The correctives are listed in Section 26 Priority 7. The first one (increase timeout/retries in Dockerfile) is recommended.

Once the rebuild is validated (Total paths: 8, packages importable in the container after force-recreate), Priority 6 (route migration) can start.

After Priority 6 is validated (routes return 200 with a valid JWT, 401 without, 400 without X-Organization-Id, 403 with inactive membership), Priority 8 (provisioning) and Priority 9 (tests) follow.

Do not restart the project.
Do not repeat completed inspections.
Do not reproduce Version 12 as if Priority 5 had not been implemented.
Do not invent implementation details.
Do not weaken security to pass tests.
Do not skip the rebuild. It is not cosmetic; it is required for the API to survive a restart.

Immediate next step: apply the Dockerfile pip timeout/retries correction, then docker compose build api, then docker compose up -d --force-recreate api, then verify 8 paths and package versions.

Preserve all existing data, Docker volumes, database security boundaries and unrelated containers.

29. FINAL HANDOVER RULE

Continue SecureBiz Lab from this exact Version 13 state.

The project has completed Priority 5 (Authentication and Session Management). All 9 functional tests (P1-P8 and P11) passed on 12 November 2026 with real DB state verification.

The next phase is the rebuild of the API image (prerequisite), followed by Priority 6 (migration of IAM routes to JWT), Priority 8 (provisioning), and Priority 9 (tests and state_check extension).

Do not restart the project.
Do not repeat completed inspections.
Do not reproduce Version 12 as if Priority 5 had not been implemented.
Do not invent implementation details.
Do not weaken security to pass tests.
Do not skip the rebuild.

Immediate next step: apply the Dockerfile pip timeout/retries correction, then rebuild the image, then Priority 6.

Preserve all existing data, Docker volumes, database security boundaries and unrelated containers.

--- FIN DU MESSAGE 3/3 ---
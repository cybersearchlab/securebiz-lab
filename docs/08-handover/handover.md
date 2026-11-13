MASTER HANDOVER PROMPT — SECUREBIZ LAB
Version 14.3 — Priority 5, Priority 6, Priority 8, Priority 9, and Priority 10 Complete;
Vault Provisioning Separated; 132 Tests; Ready for Phase 7 (DevSecOps)
Snapshot date: 13 November 2026
Project directory: C:\Users\nguey\Documents\SecureBiz-Lab
Environment: Windows 11, PowerShell (5.1), Docker Desktop with WSL2,
  Python 3.12 in the API container, PostgreSQL 16, FastAPI, psycopg,
  HashiCorp Vault 1.20 (dev mode, inmem), pgsodium 3.1.9.

1. PURPOSE AND OPERATING INSTRUCTIONS
You are taking over an ongoing technical and security engineering project named SecureBiz Lab.

This document is the consolidated Version 14.1 handover. It supersedes Version 13.

It incorporates:

The complete Priority 5 implementation (JWT authentication, refresh tokens,
  authentication routes, authenticated dependencies).
The complete Priority 6 implementation (migration of IAM routes to JWT
  authentication, migration of the isolation test to httpx.AsyncClient +
  ASGITransport).
The complete Priority 8 implementation (dedicated PostgreSQL role
  securebiz_provisioner, Vault policy provisioner-read, two scripts:
  scripts/set_provisioner_password.py and scripts/provision_user.py,
  Argon2id provisioning tested end-to-end).
The rebuild of the API image, now persisted with all Priority 5 packages.
The Vault restart on 12 November 2026 (inmem storage), and the full
  re-provisioning of all Vault secrets (JWT, provisioner, policy, token).
The cleanup of the refresh-token store after the functional tests.
All functional test results: 9/9 for Priority 5 (P1-P8 and P11),
  4/4 for Priority 6 (F2), 1/1 end-to-end provisioning test for Priority 8.
The operational and technical corrections discovered during Priority 5,
  Priority 6, and Priority 8.
The current git state: 5 commits, origin/main aligned on 83071f1.
The exact continuation point: Priority 9 (extended tests and state_check
  extension), followed by Priority 10 (hygiene and deprecations).

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

1.4 Operational pitfalls — consolidated list (v12, v13, v14)

1.4.1 httpx.ASGITransport does NOT inject cookies set via cookies.set()
When using httpx.AsyncClient or httpx2.AsyncClient with ASGITransport(app=app), cookies added via client.cookies.set(...) are stored in the jar but NOT sent in the Cookie header of subsequent requests.
Verified: client.cookies.clear() then client.cookies.set("refresh_token", token, domain="testserver", path="/auth") then client.post("/auth/refresh") sends no cookie. The server returns 401 with detail "Refresh token required." (cookie absent), not "Invalid refresh token." (cookie present but invalid).
Corrective: send the cookie via an explicit header: client.post("/auth/refresh", headers={"Cookie": f"refresh_token={token}"}). This works for both httpx and httpx2.
This is a known limitation of the ASGI transport in both packages. TestClient of Starlette 1.10.0 inherits it.

1.4.2 TestClient requires httpx2
fastapi.testclient.TestClient imports starlette.testclient which raises RuntimeError if httpx2 is not installed. httpx2 is a separate package from httpx (version 2.16.0, with httpcore2 and truststore). Installing httpx2 via pip install httpx2 was needed.
Both httpx and httpx2 have the cookie limitation described in 1.4.1. Using httpx.AsyncClient directly with explicit Cookie header avoids the dependency on httpx2 for tests. httpx2 remains needed only if TestClient is used.
New in v14: tests/test_isolation.py uses httpx.AsyncClient directly, not TestClient. httpx2 remains installed in the image for compatibility but is not required by the current test suite.

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
PyPI timeouts (ReadTimeoutError on files.pythonhosted.org) are transitory on WSL2. Retry usually succeeds. Verified: the Priority 5 image was successfully rebuilt on 12 November 2026 despite two earlier ReadTimeoutError failures.

1.4.9 New in v14 — static guards in PowerShell match docstrings, not just code
A naive guard such as if ($writtenSource.Contains("TestClient")) { throw ... } matches the substring in docstrings and comments as well as in executable code.
Verified during Priority 6: a rewritten tests/test_isolation.py whose docstring mentioned TestClient and httpx2 triggered the guard even though the executable code did not import either package.
Corrective: either restrict the guard to executable lines (fragile in PowerShell), or reformulate docstrings to avoid the forbidden substrings entirely. The latter is the approach used in the final tests/test_isolation.py.

1.4.10 New in v14 — _logout() in a finally block must assert its response
If a test logs in and revokes its refresh family in a finally block, an unconditional _logout() will silently ignore a 503 from the server, leaving an active refresh family in the database.
Verified during Priority 6: the corrected _logout() asserts response.status_code == 200 and response.json()["status"] == "logged out". A cleanup failure therefore fails the test instead of being masked by the finally block.

1.4.11 New in v14 — any test that calls /auth/login creates a refresh-token family
Each successful POST /auth/login creates a new row in auth_session.refresh_tokens with a fresh family_id.
Verified during Priority 6: the three authenticated tests in tests/test_isolation.py created three families, all revoked via POST /auth/logout in their finally block. The test test_no_jwt_rejected creates none because it does not log in.
Rule: every test that calls /auth/login must revoke its family via POST /auth/logout with the explicit Cookie header in a finally block.

1.4.12 New in v14 — revoke_family(family_id) is a silent no-op on an unknown family
Verified by full-body inspection of app/services/refresh.py on 12 November 2026: revoke_family acquires the family-level advisory lock, executes UPDATE ... SET revoked_at = clock_timestamp() WHERE family_id = %s AND revoked_at IS NULL, and calls conn.commit(). There is no prior SELECT. On an unknown family_id, the UPDATE affects zero rows, the COMMIT succeeds, and the function returns None.
Consequence: revoke_family is safe to call in a loop over a list of family_id values, without per-call exception handling.

1.4.13 New in v14 — WriteAllText without BOM removes an existing UTF-8 BOM
[System.IO.File]::WriteAllText(path, text, [System.Text.UTF8Encoding]::new($false)) writes UTF-8 without BOM. If the previous file had a UTF-8 BOM, the BOM is silently removed.
Verified during Priority 6: the four files modified in commit a65f27b had their BOM removed as a side effect of the rewrite helper. Python 3 handles BOM-less UTF-8 files correctly, so the impact is cosmetic, but the diff includes the BOM removal.
Rule: when rewriting an existing file, either preserve the BOM if the original had one, or document the BOM removal in the commit message.

1.4.14 New in v14 — git converts LF to CRLF on checkout (core.autocrlf)
git emits warnings such as "warning: in the working copy of 'app/api/routes/roles.py', LF will be replaced by CRLF the next time Git touches it".
This is a Windows-specific line-ending policy, not a code defect. It does not affect Python execution, psycopg, or the tests.
Rule: do not treat this warning as a failure. If a strict line-ending policy is desired, add a .gitattributes file (out of scope for Priority 6).

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

As of Version 14.1, the authentication portion of this chain is fully implemented and tested for the /auth/* endpoints AND for the IAM routes (/users, /organizations/me, /roles), which now use get_authenticated_tenant_context (JWT + X-Organization-Id). The debug-header path (get_tenant_context) remains defined in app/api/dependencies.py for backward compatibility but is no longer used by the IAM routes.

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

3.5 Image build state — REBUILT in v14 (supersedes v13 §3.5)
The securebiz-lab-api:latest image was successfully rebuilt on 12 November 2026.

Verified state (12 November 2026):

Image ID: 3c0514b01d3b (sha256:3c0514b01d3bb0c031c533e4798b1b07efc5d78f07c3624da560b806344f8d7e).
Size: 305 MB.
Created: 12 November 2026, after the Priority 5 closure.

Packages verified inside the image (docker run --rm securebiz-lab-api ...):

jwt 2.10.1
argon2 25.1.0
email-validator 2.2.0
httpx 0.28.1

Packages verified inside the running container (docker exec securebiz-api ...):

jwt 2.10.1
argon2 25.1.0
email-validator 2.2.0
httpx 0.28.1

The container securebiz-api is running from the same image as securebiz-lab-api:latest (identical image IDs, sha256:3c0514b0...). There is no lag between the image and the container.

Consequence: the critical technical debt documented in v13 §3.5 is RESOLVED. A container restart (crash, docker compose restart api, Windows reboot) will NOT lose the Priority 5 packages. A docker compose up -d --force-recreate api is now safe for the API image.

The commit 158aeb4 feat(priority5): JWT auth + refresh tokens + auth routes + rebuild is the trace of this rebuild. The prior PyPI timeout failures (ReadTimeoutError) were transitory and did not block the final rebuild.

3.5.1 Vault restart and re-provisioning — 12 November 2026 (new in v14.1)

During the evening session of 12 November 2026, the securebiz-vault container
was found in Exited (255) state. The API container was crash-looping on
init_vault_key() because the Docker DNS name 'vault' did not resolve.

Cause: the Vault container had been stopped externally (Docker Desktop or
manual stop). Vault uses Storage Type: inmem, so all secrets were lost on
restart:
  - transit key securebiz-context (recreated automatically by init_vault_key())
  - secret/data/securebiz/jwt (lost, re-provisioned)
  - secret/data/securebiz/provisioner (lost, re-provisioned)
  - policy provisioner-read (lost, re-applied from vault/policies/provisioner-read.hcl)
  - token provisioner-script (lost, recreated with -ttl=8h -explicit-max-ttl=24h)

Re-provisioning performed:
  - JWT secret: new 32-byte value generated with RandomNumberGenerator
    (PowerShell). Written as version 2 then version 3 (double write, see
    pitfall 27). current_kid is v2 (cosmetic).
  - Provisioner secret: new 32-byte password written to
    secret/data/securebiz/provisioner (key db_password, version 1).
  - Policy provisioner-read: re-applied from the HCL file on disk.
  - Token provisioner-script: recreated (new accessor, 8h TTL).

Persistent state after restart:
  - PostgreSQL data (users, memberships, organizations, credentials table
    schema) is intact. Only Vault secrets were lost.
  - The securebiz_provisioner role in PostgreSQL still exists with its
    LOGIN attribute and password (managed by PostgreSQL, not Vault).
  - The securebiz_user password was reset to a 48-character value
    (cryptographically safe, generated with RandomNumberGenerator) and
    synchronized between PostgreSQL and .env. See Section 5.

Dette résiduelle documentée: Vault inmem means any future container restart
will lose all secrets again. Mitigation (out of scope for v14): switch to
Vault with file or Consul storage backend, or implement an automated
re-provisioning script.

4. REPOSITORY INVENTORY
The latest recursive inventory excluded .git, .venv, caches and .env.

Observed structure (updated for v14):

text
app/
    api/
        dependencies.py          (modified in Priority 5, unchanged in v14)
        routes/
            organizations.py     (modified in Priority 6 — uses get_authenticated_tenant_context)
            roles.py             (modified in Priority 6 — uses get_authenticated_tenant_context)
            users.py             (modified in Priority 6 — uses get_authenticated_tenant_context)
            auth.py              (new in Priority 5, unchanged in v14)
    core/
        config.py                (modified in Priority 5, unchanged in v14)
        database.py              (modified in v12, unchanged in v14)
        jwt.py                   (new in Priority 3, unchanged in v14)
        vault.py                 (modified in Priority 2, unchanged in v14)
    schemas/
        auth.py                  (new in Priority 5, unchanged in v14)
    services/
        context_signing.py       (unchanged in v14)
        refresh.py               (rewritten in Priority 4, unchanged in v14)
    main.py                      (modified in Priority 5, unchanged in v14)

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
    test_isolation.py            (rewritten in Priority 6 — JWT + ASGITransport)

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
app/api/routes/users.py	User routes (JWT as of Priority 6)
app/api/routes/organizations.py	Organization routes (JWT as of Priority 6)
app/api/routes/roles.py	Role routes (JWT as of Priority 6)
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
tests/test_isolation.py	Tenant-isolation tests (JWT + ASGITransport as of Priority 6)

4.1 Git history — VERIFIED 13 November 2026 (supersedes v14.2 §4.1)
git is available (2.56.0.windows.4). The repository root is C:/Users/ngu ey/Documents/SecureBiz-Lab, branch main, not a shallow clone.

Verified commit list (git log --oneline, 13 November 2026):

text
0c702d7 (HEAD -> main, origin/main) refactor(priority10): move Vault provisioning to scripts/init_vault.py
02b1e8f                              refactor(priority10): remove dead get_tenant_context dependency
7b9bd9e                              docs(priority10): document psycopg.connect() context manager behaviour
6886a27                              chore(priority10): migrate to lifespan and fix deprecated status code
198f1bc                              chore(priority10): add .gitattributes and extend .gitignore
de63f03                              test(priority9-followup): add real-PostgreSQL integration tests for refresh
07b5112                              test(priority9-followup): add transaction lifecycle tests for get_authenticated_tenant_context
4e79a01                              test(priority9-followup): add /users and /roles isolation tests
a30e575                              docs(v0.5.2): update handover to v14.2 (Priority 9 close)
26eade2                              docs(v0.5.1): close Priority 9 (tests, state_check v4, documentation)
dc022c0                              test(priority9): extend state_check.py to v4 (10 checks)
986f913                              test(priority9): add provisioning CLI tests (11 tests, mocked Vault/DB)
dd4be83                              test(priority9): add auth route tests (18 tests, mocked services)
5a47261                              test(priority9): add refresh service unit tests (31 tests, mocked DB)
1cf9ac2                              test(priority9): add JWT unit tests (38 tests, no DB/Vault)
83071f1                              feat(priority8): provisioner role, Vault policy, Argon2id provisioning scripts, and v14 handover
c00e0c3                              docs(v0.5.0): update documentation for Priority 8 (provisioning)
a65f27b                              feat(priority6): migrate IAM routes and isolation test to JWT auth
ff7d60a                              docs(v0.4.0): update documentation for Priority 5
158aeb4                              feat(priority5): JWT auth + refresh tokens + auth routes + rebuild
2362024                              feat: v0.3.0 - validated cryptographic architecture (Vault + pgsodium + RLS)

The v13 §4.1 statement "the repository contains exactly one commit" is
OBSOLETE. There are five commits as of 12 November 2026 (evening).

The v13 §4.1 statement "the Priority 5 changes (9 files) have not been
committed yet" is OBSOLETE. Priority 5 is committed in 158aeb4.

The v13 §28 statement "git commit / push of Priority 5 changes — PENDING"
is OBSOLETE.

The v14 §4.1 statement "there are four commits" is OBSOLETE. Priority 8
added a fifth commit (83071f1).

The new commit 83071f1 contains:
  - database/migrations/003_provisioner_role.sql
  - vault/policies/provisioner-read.hcl
  - scripts/set_provisioner_password.py
  - scripts/provision_user.py
  - docs/08-handover/handover.md (v13 → v14 update)

5 files changed, 995 insertions(+), 314 deletions(-).

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

4.4 Git working tree — verified 12 November 2026 (evening)

After the Priority 8 commit (83071f1), the working tree is clean:

text
git status --short
(empty)

No unstaged changes, no untracked files, no leftover .bak-v13 or .bak-v14
backups.

Note: .gitignore currently contains `.env`, `__pycache__/`, `*.py[cod]`,
`.venv/`, `venv/`, `.pytest_cache/`, `.coverage`, `*.bak`. It does NOT
contain `.env.backup-*` or `*.bak-*`. These entries should be added in a
future hygiene commit (Priority 10).

5. ENVIRONMENT VARIABLES — VERIFIED NAMES AND BEHAVIOR
The .env file was inspected safely. Only variable names and lengths were displayed.

Current state (verified 11 November 2026 after recovery, unchanged in v14):
.env change on 12 November 2026 (evening):

The POSTGRES_PASSWORD value was reset to a new 48-character
cryptographically-safe value (generated with RandomNumberGenerator) and
synchronized between PostgreSQL (ALTER ROLE securebiz_user) and .env.
The old 15-character value was replaced.

This change was made because the script set_provisioner_password.py could
not authenticate as securebiz_user via SCRAM-SHA-256 with the .env value
(password authentication failed). After regeneration, a direct psycopg
connection test from the securebiz-api container confirmed
"CONNECTION_OK: securebiz_user".

The .env round-trip was verified: the value read back from .env matches
the value used for ALTER ROLE (exact match, 48 chars, 1 occurrence).

Note: no value is displayed here. The .env is local and ignored by git.

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

The JWT HS256 secret is NOT in .env. It lives in Vault KV at secret/data/securebiz/jwt. This is by design (centralized secret management, audit, rotation).

6. LIVE POSTGRESQL ROLE CONFIGURATION
Verified live on 11 November 2026. Unchanged in v14.

Roles:

Role	LOGIN	SUPERUSER	INHERIT	BYPASSRLS
securebiz_app	Yes	No	No	No
securebiz_auth	Yes	No	Yes	No
securebiz_owner	No	No	Yes	No
securebiz_user	Yes	Yes	Yes	Yes

securebiz_provisioner (new in Priority 8, commit 83071f1):

Role        LOGIN  SUPERUSER  INHERIT  BYPASSRLS  CREATEROLE  CREATEDB  REPLICATION
securebiz_provisioner  Yes   No        No       No         No          No        No

Attributes verified (after activation on 12 November 2026 evening):
  - rolcanlogin = t (activated via ALTER ROLE ... WITH LOGIN PASSWORD)
  - rolsuper = f
  - rolcreatedb = f
  - rolcreaterole = f
  - rolinherit = f (NOINHERIT, explicit)
  - rolreplication = f
  - rolbypassrls = f
  - No role memberships (pg_auth_members returns 0 for this role)

Purpose: dedicated role for Argon2id credential provisioning. It can only
INSERT into auth_private.credentials. It cannot SELECT, UPDATE, or DELETE.
It is never used by the API runtime.

Password storage: the role password is stored in Vault KV-v2 at
secret/data/securebiz/provisioner (key db_password). The password is
never in .env, never in git, never displayed.

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
Verified live on 11 November 2026. Unchanged in v14.

auth_private (updated v14.1):
securebiz_auth: USAGE.
securebiz_owner: USAGE.
securebiz_app: no USAGE.
securebiz_provisioner: USAGE (new in Priority 8).
PUBLIC: no listed privileges.
securebiz_user: USAGE and CREATE.

securebiz_provisioner has USAGE on the schema but only INSERT on
auth_private.credentials. It has no SELECT, UPDATE, or DELETE on that table.

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
The live ACL query returned 111 rows (before migration 002). After migration 002, auth_session.refresh_tokens is added. Unchanged in v14.

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

The table contains exactly 1 row (the test credential created on 12 November 2026 for user a2c643f2-7212-4693-bc7f-d220cb9cdaf4, email test-user@test.com). The password hash is Argon2id with parameters time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16. The hash itself must never be displayed.

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

8.8 auth_session.refresh_tokens content — verified 12 November 2026 (new in v14)
The table contains 11 rows. All 11 rows have revoked_at NOT NULL. Active tokens: 0.

Chronological breakdown (issued_at in UTC, 12 November 2026):

#	issued_at	revoked_at	family status
1	12:20:16.586	NULL (later revoked manually)	revoquée
2	14:09:08.996	NULL (later revoked manually)	revoquée
3	14:09:35.044	NULL (later revoked manually)	revoquée
4	14:09:58.287	NULL (later revoked manually)	revoquée
5	14:10:08.856	NULL (later revoked manually)	revoquée
6	14:10:18.431	NULL (later revoked manually)	revoquée
7	14:10:27.604	NULL (later revoked manually)	revoquée
8	14:24:47.930	14:24:47.957	revoquée (empirical pre-F2 test)
9	14:42:18.464	14:42:18.548	revoquée (F2 test 1)
10	14:42:18.629	14:42:18.682	revoquée (F2 test 2)
11	14:42:18.766	14:42:18.793	revoquée (F2 test 3)

Origin of each group:

Rows 8-11 were revoked automatically by their respective callers: row 8 by the empirical pre-F2 login+logout test (separate from the test suite), rows 9-11 by the three authenticated tests in tests/test_isolation.py via the asserted _logout() helper in each test's finally block.

Rows 1-7 were pre-existing residues from earlier test runs (12:20 and 14:09-14:10). They were revoked manually on 12 November 2026 via seven calls to revoke_family(family_id) from the application service layer (securebiz_auth, family-level advisory lock, explicit COMMIT). No direct SQL UPDATE, no DELETE, no RLS change.

Verified current state:
sql
SELECT count(*) AS total, count(*) FILTER (WHERE revoked_at IS NULL) AS active FROM auth_session.refresh_tokens;
-- 11|0

Do not modify the table without inspecting the schema (column names: id, user_id, family_id, token_hash, issued_at, expires_at, revoked_at, replaced_by, user_agent, ip_address) and the revocation model (§22.3). Never DELETE rows; revocation is by UPDATE revoked_at.

8.9 securebiz_provisioner privileges — verified 12 November 2026 (new in v14.1)

The role securebiz_provisioner was created by migration 003 with:

  CREATE ROLE securebiz_provisioner
      NOLOGIN
      NOSUPERUSER
      NOCREATEDB
      NOCREATEROLE
      NOINHERIT
      NOREPLICATION
      NOBYPASSRLS;

  GRANT USAGE ON SCHEMA auth_private TO securebiz_provisioner;
  GRANT INSERT ON TABLE auth_private.credentials TO securebiz_provisioner;

The role was initially NOLOGIN (fail-closed). It was activated later via
ALTER ROLE securebiz_provisioner WITH LOGIN PASSWORD '<value from Vault>',
executed by scripts/set_provisioner_password.py.

Effective privileges verified (after activation):

  has_schema_privilege('securebiz_provisioner', 'auth_private', 'USAGE')
    = true
  has_table_privilege('securebiz_provisioner', 'auth_private.credentials',
    'INSERT') = true
  has_table_privilege('securebiz_provisioner', 'auth_private.credentials',
    'SELECT') = false
  has_table_privilege('securebiz_provisioner', 'auth_private.credentials',
    'UPDATE') = false
  has_table_privilege('securebiz_provisioner', 'auth_private.credentials',
    'DELETE') = false

End-to-end test (12 November 2026):
  - Created a throwaway user (id 00000000-0000-0000-0000-00000000a001,
    email provision-test@example.com) in public.users.
  - Ran scripts/provision_user.py --user-id <uuid> --generate.
  - The script read the provisioner password from Vault, hashed the new
    password with Argon2id (same parameters as auth.py), and inserted the
    credential as securebiz_provisioner.
  - Verified POST /auth/login with the generated password returns 200 with
    an access_token.
  - Cleaned up: deleted the credential and the throwaway user.

No DELETE was performed on auth_private.credentials by the role itself.
The cleanup was done via securebiz_user for test hygiene only.

9. LIVE RLS FLAGS
Verified live on 11 November 2026. Unchanged in v14.

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
Status: COMPLETED on 11 November 2026. Unchanged in v14.

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

No RLS policy has been modified as part of these inspections, nor during Priority 5 or Priority 6.

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

11.1 app/core/vault.py
Full code is preserved in the transcript. Key points:

VAULT_TOKEN is read from environment, RuntimeError immediately if missing (fail-fast at module load).
init_vault_key() is idempotent: handles 400 already mounted, 404 key absent -> create, 200 key exists, 403 token, 5xx.
sign_payload() validates the signature output: 64 bytes exactly, prefix vault:v, key_version >= 1.
requests.exceptions.RequestException is caught and re-raised as RuntimeError.

get_jwt_secret() is implemented.
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

11.2 app/services/context_signing.py
Full code is preserved in the transcript. Key points:

Separation is clean: no DB, no HTTP handler, no auth validation.
_validate_uuid(): strict (non-empty, valid UUID, rejects nil UUID).
build_payload(): canonical JSON with iss, aud, sub, org, jti (UUID4), iat, exp. ensure_ascii=True, separators=(",", ":"), sort_keys=True.
CONTEXT_TTL_SECONDS = 30, MAX_CONTEXT_TTL_SECONDS = 60 (constants).
sign_context() returns (payload_json, sig_bytes, vault_version, key_version).
The docstring explicitly forbids authentication/JWT logic in this file.

Confirmation: sign_context() does not verify that the user exists or that the membership is active. This is by design — PostgreSQL (securebiz_install_context) performs that verification at installation time. A malicious caller can generate a signed payload with arbitrary UUIDs; PostgreSQL rejects it at install if the user/org/membership is inactive. The signature proves API origin, not content legitimacy.

11.3 app/main.py
Full code is preserved in the transcript. Key points:

FastAPI application initialization, routers registered.
@app.on_event("startup") -> init_vault_key().
/health uses get_database_session() and SELECT 1, returns 503 on OperationalError/OSError.
Root endpoint minimal.

The auth router is registered.

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
Status: The five functions listed below have already been inspected individually. Unchanged in v14.

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
Verified in the earlier inspection, unchanged in v14.

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
Verified in the earlier inspection, unchanged in v14.

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
Status: COMPLETED on 11 November 2026. Unchanged in v14.

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

Its invocation mechanism remains open: no scheduled task, administrative process or provisioning caller has yet been established.

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

The trusted administrative provisioning mechanism that calls this function has not yet been identified. Do not expose this function to the business runtime role without a separate security design.

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

The trusted administrative revocation process has not yet been identified.

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
Whether administrative key registration and revocation have a trusted operational caller. (Open.)
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
Unchanged in v14.

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
Unchanged in v14.

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
Status: COMPLETED on 11 November 2026. Unchanged in v14.

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
The complete file was supplied and inspected on 11 November 2026, and updated in Priority 5 (12 November 2026). Unchanged in v14.

Observed:

FastAPI application initialization;
registration of users, organizations, roles and auth routers;
startup handler using @app.on_event("startup");
call to init_vault_key() during startup;
root endpoint;
/health endpoint using the business database session and SELECT 1.

The health endpoint catches database connection errors and returns HTTP 503.

No user, organization or membership provisioning was visible in this file.

Router registration:

from app.api.routes.auth import router as auth_router
app.include_router(organizations_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(auth_router)

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

18. API ROUTES — INSPECTED AND EXTENDED IN v14
18.1 Users — MIGRATED to JWT in Priority 6
File:

text
app/api/routes/users.py

Observed (as of 12 November 2026, after Priority 6):

text
GET /users

Query (unchanged):

sql
SELECT id, email, status
FROM public.users
ORDER BY email;

The route uses:

python
Depends(get_authenticated_tenant_context)

Its docstring refers to RLS and users:read. Effective route-level permission enforcement is provided by the RLS policies on public.users (Section 10.3) combined with the signed context installation.

No user-creation endpoint was observed.

The previous debug-header dependency (X-Debug-User-Id, X-Debug-Org-Id) is no longer used on this route. A caller must now send Authorization: Bearer <jwt> and X-Organization-Id: <uuid>.

18.2 Organizations — MIGRATED to JWT in Priority 6
File:

text
app/api/routes/organizations.py

Observed (as of 12 November 2026, after Priority 6):

text
GET /organizations/me

Query (unchanged):

sql
SELECT id, name, slug
FROM public.organizations
LIMIT 1;

Returns 404 when no organization is found.

No organization-creation endpoint was observed.

The route uses Depends(get_authenticated_tenant_context). The debug-header dependency is no longer used.

18.3 Roles — MIGRATED to JWT in Priority 6
File:

text
app/api/routes/roles.py

Observed (as of 12 November 2026, after Priority 6):

text
GET /roles

Query (unchanged):

sql
SELECT id, name
FROM public.roles
ORDER BY name;

The docstring refers to RLS and roles:read. Actual enforcement is provided by the RLS policies on public.roles (Section 10.3) combined with the signed context installation.

No role-creation endpoint was observed.

The route uses Depends(get_authenticated_tenant_context). The debug-header dependency is no longer used.

18.4 Dependency contract in routes — verified 11 November 2026
A read-only search across app/api/routes/*.py was performed:

powershell
$patterns = '\.commit\(|\.rollback\(|\.close\(|with\s+connection|with\s+conn\b'
Get-ChildItem .\app\api\routes -Recurse -File -Filter *.py |
    Select-String -Pattern $patterns

Only three matches were returned, all of the form with connection.cursor() as cur: (in organizations.py, roles.py, users.py). These are the psycopg cursor context manager, not a connection context manager. They do not commit, rollback, or close the connection.

No occurrence of connection.commit(), connection.rollback(), connection.close(), or with connection: as a bare connection context manager was found.

A second read-only search was performed:

powershell
$patterns2 = 'get_raw_connection|get_database_connection|get_database_session|psycopg\.connect'
Get-ChildItem .\app\api\routes -Recurse -File -Filter *.py |
    Select-String -Pattern $patterns2

Result: no matches. No route opens its own connection.

Conclusion: the dependency contract — routes do not manage transactions and do not open connections — is respected empirically by all three read-only routes. This remains true after the Priority 6 migration.

Reserve: any future write route must be submitted to the same verification.

18.5 Authentication routes
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

18.6 API surface verification
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

18.7 New in v14 — Routes use of get_authenticated_tenant_context (verified 12 November 2026)
A read-only grep across app/api/routes/*.py produced:

text
app/api/routes/organizations.py:9:from app.api.dependencies import get_authenticated_tenant_context
app/api/routes/organizations.py:19:    connection: Connection = Depends(get_authenticated_tenant_context),
app/api/routes/roles.py:8:from app.api.dependencies import get_authenticated_tenant_context
app/api/routes/roles.py:18:    connection: Connection = Depends(get_authenticated_tenant_context),
app/api/routes/users.py:8:from app.api.dependencies import get_authenticated_tenant_context
app/api/routes/users.py:18:    connection: Connection = Depends(get_authenticated_tenant_context),

No occurrence of get_tenant_context in any route file. The debug-header dependency remains defined in app/api/dependencies.py but is not imported by any current route.

19. AUTH DEPENDENCIES
19.1 Existing get_tenant_context — retained, no longer used by routes
File: app/api/dependencies.py.

Uses debug headers X-Debug-User-Id and X-Debug-Org-Id.
APP_ENV guard (rejects production).
DEBUG_HEADERS_ENABLED guard (rejects when false).
sign_context + securebiz_install_context + yield + cleanup + commit/rollback + close.
Exception mapping: HTTPException -> rollback + propagate; Exception -> rollback + 500.

This function is no longer used by /users, /organizations/me, /roles as of Priority 6 (commit a65f27b). It remains defined in dependencies.py for backward compatibility, in accordance with Priority 6 step 8.

19.2 UserContext dataclass

python
@dataclass(frozen=True)
class UserContext:
    user_id: str
    jti: str

Purpose: carry the authenticated user identity from get_current_user to get_authenticated_tenant_context. Frozen to prevent accidental mutation.

19.3 get_current_user()

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

19.4 get_authenticated_tenant_context() — now used by the three IAM routes

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

Status: implemented, compiled, and used by /users, /organizations/me, /roles as of Priority 6. Tested by tests/test_isolation.py (4/4 passed).

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
Unchanged from v12 and v13.

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

21. AUTHENTICATION AND PROVISIONING — STATUS AFTER PRIORITY 5 AND PRIORITY 6
21.1 What is implemented and verified

Element    Status
All Priority 10 items (gitattributes, gitignore, lifespan, HTTP 422, dead code get_tenant_context, init_vault separation) — CLOSED on 2026-11-13.
app/core/vault.py get_jwt_secret()    Verified (32 bytes, version 3 after re-provisioning)
Vault KV secret secret/data/securebiz/jwt    Present (version 3, never displayed)
app/core/jwt.py create_access_token    Verified (HS256, kid, claims)
app/core/jwt.py verify_access_token    Verified (38/38 tests, Priority 9)
app/services/refresh.py    Rewritten (advisory locks, RefreshTokenError, RefreshTokenDatabaseError, revoke_family, revoke_family_by_raw_token)
app/schemas/auth.py    Created (LoginRequest with EmailStr, TokenResponse)
app/api/routes/auth.py    Created (/auth/login, /auth/refresh, /auth/logout)
app/api/dependencies.py    Extended (UserContext, get_current_user, get_authenticated_tenant_context)
app/api/routes/users.py    Migrated to get_authenticated_tenant_context (Priority 6)
app/api/routes/organizations.py    Migrated to get_authenticated_tenant_context (Priority 6)
app/api/routes/roles.py    Migrated to get_authenticated_tenant_context (Priority 6)
tests/test_isolation.py    Rewritten with httpx.AsyncClient + ASGITransport, 4 tests, asserted logout cleanup (Priority 6)
tests/test_jwt.py    New in Priority 9, 38 tests (create/verify, 18 positive + 20 negative), no DB/Vault
tests/test_refresh.py    New in Priority 9, 31 tests (mocked DB, real Argon2id), all scenarios
tests/test_auth_routes.py    New in Priority 9, 18 tests (mocked services, /auth/login, /auth/refresh, /auth/logout)
tests/test_provision_user.py    New in Priority 9, 11 tests (mocked Vault + DB, real Argon2id, error paths)
tests/conftest.py    New in Priority 9, minimal env vars for pytest
scripts/state_check.py    v4 (Priority 9), 16 checks (was 6), dynamic Vault key read
app/main.py    auth_router registered (8 paths verified)
requirements.txt    PyJWT==2.10.1, argon2-cffi==25.1.0, email-validator==2.2.0 added
Packages in running container    PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1
Packages persisted in image    YES (rebuilt 12 November 2026, verified with docker run --rm)
auth_private.credentials    1 row (test credential, Argon2id)
auth_session.refresh_tokens    17 rows, 0 active (all revoked)
auth_session active_tokens    0
public.users    1 row (status = active)
public.memberships    1 row (status = active)
Priority 5 tests    P1-P8 (8/8) + P11 (1/1) all passed
Priority 6 tests    F2 4/4 passed
Priority 9 tests    JWT 38/38, Refresh 31/31, Auth routes 18/18, Provisioning 11/11 (host); Isolation 4/4 (container)
Priority 10 tests    .gitattributes added, .gitignore extended, lifespan migrated, HTTP 422 constant updated
Priority 10 tests    .gitattributes and .gitignore are config files; no test change. 108 host tests pass with -W error::DeprecationWarning.
Priority 9 state_check.py    v4, 16 checks, all OK (exit code 0)
Priority 8 tests    End-to-end provisioning test passed (1/1)
Git commit of Priority 5    Done (158aeb4)
Git commit of Priority 5 documentation    Done (ff7d60a)
Git commit of Priority 6    Done (a65f27b)
Git commit of Priority 8 documentation    Done (c00e0c3)
Git commit of Priority 9    Done (1cf9ac2, 5a47261, dd4be83, 986f913, dc022c0, 26eade2)
Git commit of Priority 10    Done (198f1bc, 6886a27, 7b9bd9e, 02b1e8f, 0c702d7, 6bb3db7, 755ea2e, 3a8f2a5)
Git push of all commits    Done (origin/main on 3a8f2a5)
Migration 003 applied    securebiz_provisioner created (NOLOGIN, then activated)
Vault policy provisioner-read    Applied (read on secret/data/securebiz/provisioner)
Vault token provisioner-script    Created (8h TTL, read-only)
scripts/set_provisioner_password.py    Created, env-aware, fail-safe rollback
scripts/provision_user.py    Created, Argon2id params confirmed against auth.py
scripts/init_vault.py    Created (Priority 10, admin-only Vault provisioning)
Provisioning test (provision_user.py)    Passed end-to-end (login 200)

21.2 What is NOT implemented

Element    Status
All Priority 10 items (gitattributes, gitignore, lifespan, HTTP 422, dead code get_tenant_context, init_vault separation) — CLOSED on 2026-11-13.


Vault persistent backend (file, Consul) or automated re-provisioning    Pending — v15
Store provisioner-script token in a local file (not in memory)    Pending — v15
Automate Vault/PG public key synchronization after Vault restart    Pending — v15
21.3 Provisioning searches already performed
Repository-wide searches for INSERT INTO users, INSERT INTO memberships, create_user, create_membership, provision_user, seed_user, seed_data, create_organization returned nothing. Migration inspection confirmed no user/organization/membership provisioning routine. Git history confirmed no committed INSERT statement.

Only the auth_private.credentials table has been manually populated (1 row), via psql as securebiz_user, for the test user a2c643f2-7212-4693-bc7f-d220cb9cdaf4. This is a test credential, not a provisioning mechanism.

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

TCP connection from the API container to securebiz_auth was successful.

22. PASSWORD HASHING AND JWT — IMPLEMENTED DECISIONS
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

Schema of auth_session.refresh_tokens (verified 12 November 2026 via information_schema.columns):
- id uuid NOT NULL, DEFAULT gen_random_uuid()
- user_id uuid NOT NULL
- family_id uuid NOT NULL
- token_hash bytea NOT NULL
- issued_at timestamptz NOT NULL, DEFAULT clock_timestamp()
- expires_at timestamptz NOT NULL
- revoked_at timestamptz NULL
- replaced_by uuid NULL
- user_agent text NULL
- ip_address inet NULL

Concurrency:
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

revoke_family(family_id) flow (verified 12 November 2026, full body):
1. get_auth_connection().
2. with conn.cursor() as cur: _acquire_family_lock(cur, family_id).
3. UPDATE auth_session.refresh_tokens SET revoked_at = clock_timestamp() WHERE family_id = %s AND revoked_at IS NULL.
4. conn.commit().
5. On psycopg.Error: rollback, raise RefreshTokenDatabaseError("failed to revoke family") from None.
6. finally: _close_quietly(conn).
Idempotent. No exception on missing family (the UPDATE affects zero rows and the COMMIT succeeds). No prior SELECT.

revoke_family_by_raw_token(raw_token) flow (verified 12 November 2026, full body):
1. If raw_token is not str or empty -> return (silent no-op).
2. token_hash = SHA-256(raw_token).
3. SELECT family_id FROM auth_session.refresh_tokens WHERE token_hash = %s (no lock).
   If None -> conn.rollback(); return (silent no-op).
4. _acquire_family_lock(cur, family_id).
5. UPDATE ... SET revoked_at = clock_timestamp() WHERE family_id = %s AND revoked_at IS NULL.
6. conn.commit().
Idempotent. Unknown token -> silent no-op. Used by /auth/logout.

Exception separation:
- RefreshTokenError (ValueError): business validation (unknown token, expired, reuse detected, invalid state). Mapped to 401.
- RefreshTokenDatabaseError (RuntimeError): database failure. Deliberately does NOT inherit from RefreshTokenError, so a caller's except RefreshTokenError cannot swallow a DB failure. Mapped to 503.

Both inherit from different bases on purpose. This separation was introduced in Priority 5 (Bloc B1bis).

23. TESTING AND VALIDATION — PRIORITY 5 AND PRIORITY 6
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

23.2 Priority 6 functional tests — executed 12 November 2026
tests/test_isolation.py (4/4 passed):

Test	Assertion	Result
test_access_own_organization	200 + json["id"] == ORG_A	PASSED
test_cross_tenant_access_rejected	403 + "detail" in json	PASSED
test_no_jwt_rejected	401 + detail == "Authentication required."	PASSED
test_no_organization_header_rejected	400 + detail == "Header X-Organization-Id is required."	PASSED

The pytest run also emitted two DeprecationWarning messages about @app.on_event("startup") in app/main.py. These warnings are expected and documented as known technical debt (Section 24.2). They are not failures.

Cleanup: each of the three authenticated tests calls /auth/logout in a finally block with an explicit Cookie header, and asserts status_code == 200 and status == "logged out". The cleanup is verified by the final database state (Section 23.3).

23.3 Database state after Priority 6 (verified 12 November 2026)
sql
SELECT count(*) AS total, count(*) FILTER (WHERE revoked_at IS NULL) AS active FROM auth_session.refresh_tokens;
-- 11|0

Breakdown of the 11 rows (chronological):
- 12:20:16 — 1 row, pre-existing residue, revoked manually via revoke_family.
- 14:09:08 to 14:10:27 — 6 rows, pre-existing residues, revoked manually via revoke_family.
- 14:24:47 — 1 row, empirical pre-F2 login+logout, revoked automatically.
- 14:42:18 — 3 rows, F2 authenticated tests, revoked automatically via asserted _logout().

No active refresh tokens remain. No DELETE was performed. No RLS was modified. No direct UPDATE was executed outside the application service layer.

23.4 Historical results (from v12)
Check	Historical result
pytest	3/3 passed
Bandit 1.9.4	0 findings
pip-audit 2.10.1	no known vulnerabilities at the time
scripts/state_check.py	4 OK, 6 skipped

scripts/state_check.py performs an end-to-end install_context + get_context test with rollback, but does not call get_user_status or the three administrative functions.

23.5 Test files
Bloc C — jwt.py unit tests: 18/18 passed (P1-P3 + N1-N15). Covered: valid token, wrong algorithm (none, RS256), wrong kid, wrong iss/aud, expired, wrong token_type, non-canonical sub/jti, missing required claim, tampered signature, create with non-canonical UUID.

Bloc E2 v7 — refresh endpoints: 8/8 passed. See §23.1.
Bloc E2 bis v4 — disabled user: 1/1 passed. See §23.1.
Priority 6 tests/test_isolation.py: 4/4 passed. See §23.2.

23.6 Not yet tested
- JWT via Authorization: Bearer on /users and /roles (F2 covers /organizations/me only)
- Full transaction lifecycle edge cases (cleanup failure, commit failure, rollback failure, connection close on each path)
- state_check.py extended coverage (auth_session.refresh_tokens, get_user_status, credentials)
- .gitattributes CRLF/LF policy

### 23.7 Priority 9 and Priority 10 tests — added 2026-11-13

The nine test files persisted after Priority 9 and Priority 10:

| File | Tests | Environment | Result | Commit |
|---|---|---|---|---|
| `tests/test_jwt.py` | 38 | Host (no DB/Vault, mocked secret) | 38/38 | `1cf9ac2` |
| `tests/test_refresh.py` | 31 | Host (mocked `get_auth_connection`) | 31/31 | `5a47261` |
| `tests/test_auth_routes.py` | 18 | Host (mocked services, real Argon2id) | 18/18 | `dd4be83` |
| `tests/test_provision_user.py` | 11 | Host (mocked Vault + DB, real Argon2id) | 11/11 | `986f913` |
| `tests/test_dependencies_lifecycle.py` | 10 | Host (mocked connection, ordering checks) | 10/10 | `07b5112` |
| `tests/test_isolation.py` | 4 | Container (`db:5432`, `vault:8200`) | 4/4 | `a65f27b` (Priority 6) |
| `tests/test_isolation_users.py` | 4 | Container (JWT + real DB) | 4/4 | `4e79a01` |
| `tests/test_isolation_roles.py` | 4 | Container (JWT + real DB) | 4/4 | `4e79a01` |
| `tests/test_refresh_db.py` | 12 | Container (real PostgreSQL, constraints) | 12/12 | `de63f03` |

**Total: 132 tests** (108 host + 24 container).

Known limitations of the mocked tests:

- Mocked DB (`test_refresh.py`, `test_auth_routes.py`) does not exercise
  PostgreSQL advisory locks, RLS policies, constraints, or concurrency.
  The real behaviour is covered by `test_refresh_db.py` (container).
- `test_provision_user.py` mocks `requests.get` (Vault) and
  `psycopg.connect`. Real Argon2id hashing is exercised.
- `tests/conftest.py` sets `VAULT_TOKEN` before any `app.*` import,
  because `app/core/vault.py` checks it at module load (line 45).
- `test_dependencies_lifecycle.py` uses `attach_mock()` on a parent mock
  to verify the chronological order of transaction lifecycle calls
  (install -> cleanup -> commit -> close on success; install -> rollback
  -> close on error).
- `test_refresh_db.py` creates its own families and revokes them in a
  `finally` block. It does not touch the 32 existing rows / 2 active
  residual families. It uses `securebiz_auth`, never the superuser.
  SQL constraint violations are isolated with SAVEPOINT.

24. CONSOLIDATED SECURITY ASSESSMENT
24.1 Positive findings

v12 base (unchanged):
- securebiz_app is non-superuser and has no BYPASSRLS.
- securebiz_auth is non-superuser and has no BYPASSRLS.
- securebiz_owner is NOLOGIN, non-superuser and has no BYPASSRLS.
- No role memberships involving the four inspected roles were returned.
- securebiz_app cannot use auth_private.
- securebiz_auth cannot use auth_security.
- securebiz_auth has no direct credentials-table privilege.
- securebiz_auth can execute auth_private.authenticate(...).
- securebiz_owner has SELECT on credentials.
- Six tenant-sensitive public IAM tables have RLS and FORCE RLS enabled.
- The API uses securebiz_app as its business database role.
- pgsodium 3.1.9 is installed.
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
- Twenty-five SECURITY DEFINER routines belong to pgsodium (out of scope).
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
- auth_session.refresh_tokens created, owned by securebiz_user.
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

v13 additions (unchanged):
- JWT HS256 issuance verified (18/18 tests): only HS256 accepted, alg header verified, kid verified against current and previous.
- JWT verification rejects: alg=none, alg=RS256, wrong kid, wrong iss, wrong aud, expired, wrong token_type, non-canonical sub/jti, missing required claim, tampered signature, create with non-canonical UUID.
- Refresh token rotation verified (P4): same family_id, new cookie, new JWT.
- Reuse detection verified (P5): old cookie -> 401 + entire family F1 revoked.
- Logout verified (P7): family F2 revoked, cookie cleared.
- Logout idempotent (P8): 200 without cookie.
- Disabled user (P11): refresh -> 401 + F3 revoked.
- No orphan tokens after 9 tests: active_tokens = 0 in whole DB.
- Argon2id dummy hash prevents timing-based user enumeration.
- Generic 401 on all credentials failures.
- get_current_user exception mapping: 401 / 503 (Vault) / 500 (programming error).
- get_authenticated_tenant_context exception mapping: 401 / 403 / 500 / 503.
- Advisory lock on family_id: uniform order (family -> row) across rotate/revoke/revoke_by_raw.
- RefreshTokenError and RefreshTokenDatabaseError strictly separated.
- All 22 RLS policies remain untouched.
- All 8 SQL functions unchanged during Priority 5.
- All migrations unchanged during Priority 5.

v14 additions (new):
- Image rebuilt with all Priority 5 packages (Section 3.5). The critical debt from v13 §3.5 is resolved.
- Container securebiz-api runs from the rebuilt image (identical image IDs).
- Priority 5 committed (158aeb4) and pushed (origin/main up to date).
- Priority 5 documentation committed (ff7d60a).
- Priority 6 committed (a65f27b) and pushed (origin/main up to date).
- git history now shows 4 commits, not 1 (Section 4.1 corrected).
- Three IAM routes migrated to get_authenticated_tenant_context (verified by grep, Section 18.7).
- tests/test_isolation.py rewritten with httpx.AsyncClient + ASGITransport (Section 23.2, commit a65f27b).
- Each authenticated test asserts the logout cleanup (status_code == 200 and status == "logged out").
- The test cross_tenant_access_rejected requires a strict 403 (no longer accepts 403, 404, 500).
- Refresh-token store cleaned: 11 rows total, 0 active (Section 8.8, Section 23.3).
- Seven pre-existing families revoked manually via revoke_family (service layer, securebiz_auth, family-level advisory lock, COMMIT).
- No DELETE and no direct UPDATE performed against auth_session.refresh_tokens.
- Four .bak-v13 backups removed from the working tree (3 routes + 1 test).
- Working tree clean (Section 4.4).

Priority 9 (tests) findings (added 2026-11-13):
- 102 tests persisted (98 host + 4 container): 38 JWT, 31 refresh,
  18 auth routes, 11 provisioning, 4 isolation.
- `scripts/state_check.py` v4: 10 checks (was 6), dynamic Vault key read,
  strict base64 (validate=True, 32 bytes), WARN on divergence (no auto-resync).
- Vault Ed25519 public key resynchronized after container restart
  (`ccc071be...` → `757147f3...`). Manual UPDATE on
  `auth_security.public_keys`. No automation yet.
- `EXPECTED_PUBKEY_HEX` removed from `state_check.py` (obsolete after the
  2026-11-12 Vault restart). Dynamic Vault read instead.
- `tests/conftest.py` sets `VAULT_TOKEN` before any `app.*` import
  (`app/core/vault.py` validates at module load).
- `tests/test_isolation.py` needs the container: `vault:8200` and `db:5432`
  are Docker-internal DNS. On the Windows host, 3/4 tests fail
  (`VAULT_ADDR` unreachable).

Priority 10 (hygiene and deprecations) findings (added 2026-11-13):

- The API no longer provisions Vault at startup. `init_vault_key()` was
  removed from the lifespan and moved to `scripts/init_vault.py`
  (admin-only). The runtime role cannot mount a secrets engine or
  create a key. Fail-closed: if Vault was not provisioned, requests
  that need signing return 503 instead of silently recreating a key.
- `app/main.py` migrated from deprecated `@app.on_event("startup")` to
  a `lifespan` context manager (`@asynccontextmanager`). This removes
  the `DeprecationWarning: on_event is deprecated` emitted by FastAPI
  /Starlette.
- `app/api/dependencies.py`: `HTTP_422_UNPROCESSABLE_ENTITY` replaced
  by `HTTP_422_UNPROCESSABLE_CONTENT` in `_parse_uuid()`. This removes
  the `StarletteDeprecationWarning: HTTP_422_UNPROCESSABLE_ENTITY is
  deprecated` warning. Starlette 1.10.0 provides the new constant.
- `get_tenant_context()` (debug-header dependency) removed. It was dead
  code since Priority 6 migrated all IAM routes to
  `get_authenticated_tenant_context()`. No route, test, or script
  referenced it.
- `.gitattributes` added: LF/CRLF normalization, PowerShell scripts
  keep CRLF, binary files marked.
- `.gitignore` extended: `.env.backup-*` and `*.bak-*` added. Existing
  rules preserved, no duplicate.
- `with psycopg.connect(...) as conn:` closes the connection on context
  exit (verified in the container with psycopg 3.3.8: INSIDE_WITH
  conn.closed=False, AFTER_WITH conn.closed=True, AFTER_WITH cursor()
  raises OperationalError). `scripts/provision_user.py` already relies
  on this behaviour; no `finally: conn.close()` is needed.
- 108 host tests pass with `-W error::DeprecationWarning` (no more
  deprecation warnings). The 24 container tests also pass.
24.2 Findings requiring further review

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
- The current user and membership provisioning origin remains unknown as a versioned artifact.
- Password hashing is not established as a provisioning workflow.
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

v13 additions (unchanged):
- httpx.ASGITransport does not inject cookies set via cookies.set(). Use explicit Cookie header for replay scenarios.
- TestClient of Starlette 1.10.0 requires httpx2 (separate package from httpx). Tests use httpx.AsyncClient directly to avoid this dependency.
- $LASTEXITCODE is unreliable for psql and docker cp when stderr is written.
- $ErrorActionPreference = "Stop" stops PowerShell scripts on native stderr.
- users_status_check allows only 'active', 'disabled', 'pending'.
- The API image builds can fail on PyPI timeout. Mitigation: increase pip timeout/retries in Dockerfile, or use a PyPI mirror, or verify Docker MTU.

v14 additions (unchanged):
- The static guard Contains("TestClient") matches docstrings. Reformulate
  docstrings or restrict the guard to executable lines.
- _logout() in a finally block must assert its response (status_code == 200
  and status == "logged out"). Otherwise a 503 from /auth/logout is
  silently swallowed and an active session leaks.
- Any test that calls /auth/login creates a refresh-token family and must
  revoke it via /auth/logout in a finally block with an explicit Cookie
  header.
- revoke_family(family_id) is a silent no-op on an unknown family. Safe to
  call in a loop.
- WriteAllText without BOM removes an existing UTF-8 BOM. Cosmetic for
  Python 3, but visible in diffs.
- git core.autocrlf emits LF/CRLF warnings on Windows. Not a failure.
- get_tenant_context remains defined in app/api/dependencies.py but is no
  longer imported by any route. Dead code retained for backward
  compatibility per Priority 6 step 8.
- Public.permissions is not read by app_has_permission.

v14.1 additions (new in Priority 8):

- Migration 003 created securebiz_provisioner with NOLOGIN, NOSUPERUSER,
  NOCREATEDB, NOCREATEROLE, NOINHERIT, NOREPLICATION, NOBYPASSRLS.
- The role was granted USAGE on auth_private and INSERT on
  auth_private.credentials only.
- The role was initially NOLOGIN (fail-closed), then activated via
  ALTER ROLE securebiz_provisioner WITH LOGIN PASSWORD '<Vault value>'.
- The activation script set_provisioner_password.py is fail-safe: any
  verification failure triggers rollback_to_nologin() with confirmation.
- The activation script uses psycopg.sql.Identifier and psycopg.sql.Literal
  to avoid SQL injection in ALTER ROLE.
- The Vault policy provisioner-read grants only read on
  secret/data/securebiz/provisioner. No write, list, or delete capability.
- The Vault token provisioner-script has TTL 8h, max 24h, renewable, and
  only the provisioner-read policy (plus default).
- The provisioning script provision_user.py uses the same Argon2id
  parameters as app/api/routes/auth.py (single source of truth).
- The provisioning script is env-aware (VAULT_ADDR, DB_HOST, DB_PORT,
  DB_NAME) with Docker-internal defaults, and must be executed inside
  securebiz-api.
- The provisioning script translates PostgreSQL errors:
    unique_violation -> "credential already exists"
    foreign_key_violation -> "user_id does not exist"
    insufficient_privilege -> "role misconfigured"
    other -> generic database error, no SQL detail.
- End-to-end test passed: provisioned a throwaway user, login returned 200
  with access_token, cleanup succeeded.
- The securebiz_user password was reset to a 48-character
  cryptographically-safe value, synchronized between PostgreSQL and .env.
- Working tree is clean, 5 commits, origin/main aligned on 83071f1.

Priority 9 (tests) pending items (added 2026-11-13):
- Vault/PostgreSQL public key sync is manual. After any Vault restart
  (inmem storage), the Ed25519 key changes and
  `auth_security.public_keys` must be updated via securebiz_user.
- Runtime tenant-isolation tests under JWT for `/users` and `/roles`
  are still pending (F2 covers `/organizations/me` only).
- Full transaction lifecycle tests (cleanup failure, commit failure,
  rollback failure, connection close on each path) are still pending.
- `EXPECTED_PUBKEY_HEX` removed from `state_check.py`; dynamic Vault
  read used instead, WARN on divergence (no auto-resync).

Priority 10 (hygiene and deprecations) pending items (added 2026-11-13):

- All Priority 10 items (gitattributes, gitignore, lifespan migration,
  HTTP 422 constant, dead code get_tenant_context removal, init_vault
  separation) are CLOSED.
- Residual items for v15:
  - Vault persistent backend (file, Consul) or automated
    re-provisioning. Currently inmem; any Vault restart loses the
    Ed25519 key, JWT secret, and provisioner secret.
  - Store the provisioner-script token in a local file (not in memory).
    Currently recreated at each session.
  - Automate Vault/PG public key synchronization after Vault restart.
    Currently a manual UPDATE on `auth_security.public_keys` via
    `securebiz_user`.
- Residual items for Phase 7 (DevSecOps):
  - CI pipeline (GitHub Actions).
  - Automated tests on every change.
  - Security checks in the pipeline (SAST, DAST, dependency scanning).
  - Operations documentation.
  - Reproducible demonstration scenarios.
  - Final security report of the lab.
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

v13 additions (unchanged):
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

v14 additions (new):
Image rebuild of securebiz-lab-api:latest	Completed — 3c0514b01d3b, 305 MB, packages in image
Container aligned on rebuilt image	Completed — image IDs identical
Git commit of Priority 5	Completed — 158aeb4
Git commit of Priority 5 documentation	Completed — ff7d60a
Git commit of Priority 6	Completed — a65f27b
Git push of all commits	Completed — origin/main on a65f27b
Working tree clean	Completed — git status --short empty
Migration of IAM routes to get_authenticated_tenant_context	Completed — verified by grep, commit a65f27b
tests/test_isolation.py migration to JWT	Completed — 4/4 passed, commit a65f27b
Logout cleanup asserted in tests	Completed — status_code == 200 and status == "logged out"
Refresh-token store cleanup	Completed — 11 total, 0 active
Pre-existing residues revoked via service layer	Completed — 7 families revoked via revoke_family
Backup files removed	Completed — 3 F1 + 1 F2

v14.1 additions (new in Priority 8):
Migration 003 applied    Completed — securebiz_provisioner created
Vault policy provisioner-read    Completed — applied and verified
Vault token provisioner-script    Completed — 8h TTL, read-only
scripts/set_provisioner_password.py    Completed — fail-safe, env-aware
scripts/provision_user.py    Completed — Argon2id params confirmed
Provisioning end-to-end test    Completed — login 200 with access_token
JWT secret re-provisioned    Completed — version 3 (crypto-safe)
Provisioner secret re-provisioned    Completed — version 1
securebiz_user password reset    Completed — 48 chars, synchronized
Git commit of Priority 8    Completed — 83071f1
Git push of Priority 8    Completed — origin/main on 83071f1
Working tree clean    Completed — git status --short empty

Pending:
state_check.py v4 (10 checks)    COMPLETED (dc022c0)
Runtime tenant-isolation tests under JWT for /users and /roles    COMPLETED (4e79a01, 4+4 tests)
Full transaction lifecycle tests    COMPLETED (07b5112, 10 tests)
Provisioning script unit tests (tests/test_provision_user.py)    COMPLETED — Priority 9 (commit 986f913)
Removal of dead get_tenant_context    COMPLETED (02b1e8f)
app/main.py lifespan migration (on_event deprecated)    COMPLETED (6886a27)
Vault inmem persistence    OPEN — v15 automation or backend change

26. NEXT PRIORITIES

Priority 8 — Provisioning endpoint or script for Argon2id hashes (CLOSED)

Status: CLOSED on 12 November 2026 (commit 83071f1).

What was implemented:
- Migration 003: securebiz_provisioner role (NOLOGIN, INSERT only).
- Vault policy provisioner-read (read on secret/data/securebiz/provisioner).
- scripts/set_provisioner_password.py: one-shot bootstrap.
- scripts/provision_user.py: Argon2id credential provisioning.
- End-to-end test: provisioned a throwaway user, login 200, cleanup.

Argon2id parameters (confirmed against app/api/routes/auth.py):
  time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16.

Priority 9 — Tests and state_check extension (CLOSED on 2026-11-13)
- Unit tests for refresh.py: P1-P8 and P11 done manually, but not in tests/.
- Integration tests for /auth/*: manual only.
- Tenant isolation tests under JWT for /users and /roles (F2 covers
  /organizations/me only).
- Unit tests for scripts/provision_user.py (success, duplicate, missing user).
- Full transaction lifecycle tests: cleanup failure, commit failure,
  rollback failure, connection close on each path.
- Extend scripts/state_check.py to check:
  - auth_session.refresh_tokens (table exists, count, active=0)
  - auth_session.get_user_status (EXECUTE ACL, behavior)
  - auth_private.credentials (count, no hash leaked)
  - securebiz_provisioner role (attributes, privileges)

Priority 9 status (2026-11-13): CLOSED

Priority 10 status (2026-11-13): CLOSED

- .gitattributes added (LF/CRLF normalization, PowerShell, binary).
- .gitignore extended (.env.backup-*, *.bak-*).
- lifespan= replaces @app.on_event("startup") in app/main.py.
- HTTP_422_UNPROCESSABLE_CONTENT replaces the deprecated constant.
- get_tenant_context() (dead code) removed from dependencies.py.
- scripts/init_vault.py: Vault provisioning moved to an admin script.
- 5 commits: `198f1bc` (gitattributes+gitignore), `6886a27` (lifespan+HTTP422),
  `7b9bd9e` (psycopg documentation), `02b1e8f` (dead code removal),
  `0c702d7` (vault provisioning separation). Plus 3 docs commits:
  `6bb3db7` (CHANGELOG), `755ea2e` (README), `3a8f2a5` (ROADMAP).
- 108 host tests pass with -W error::DeprecationWarning.
- 24 container tests pass.
- Total: 132 tests.

Priority 9 follow-up status (2026-11-13): CLOSED

- 3 test files added: `test_isolation_users.py`, `test_isolation_roles.py`,
  `test_refresh_db.py` (12 tests, real PostgreSQL), `test_dependencies_lifecycle.py`
  (10 tests, transaction ordering).
- 4 commits: `4e79a01`, `07b5112`, `de63f03` (+ docs in `a30e575` and later).

Phase 7 (DevSecOps and Demonstration) — NEXT

- CI pipeline (GitHub Actions).
- Automated tests on every change.
- Security checks in the pipeline (SAST, DAST, dependency scanning).
- Operations documentation.
- Reproducible demonstration scenarios.
- Final security report of the lab.


- 102 tests persisted in `tests/` (98 host + 4 container).
- `scripts/state_check.py` v4: 10 checks (was 6), 16 records.
- 6 commits: `1cf9ac2` (JWT), `5a47261` (refresh), `dd4be83` (auth routes),
  `986f913` (provisioning), `dc022c0` (state_check v4), `26eade2` (docs).
- Vault Ed25519 public key resynchronized manually (`ccc071be...` →
  `757147f3...`) after container restart.
- `EXPECTED_PUBKEY_HEX` removed; dynamic Vault read + WARN on divergence.
- `/users` and `/roles` isolation under JWT: still pending (follow-up).
- Full transaction lifecycle tests: still pending (follow-up).

Priority 10 — Hygiene and deprecations (CLOSED on 2026-11-13)
- Add .gitattributes to formalize the LF/CRLF policy.
- Add .env.backup-* and *.bak-* to .gitignore.
- Migrate @app.on_event("startup") to lifespan= in app/main.py.
- Evaluate removal of get_tenant_context (dead code).
- Migrate init_vault_key() to a separate administrative path.

Priority 9 — Tests and state_check extension
- Unit tests for refresh.py: P1-P8 and P11 done manually, but not in tests/.
- Integration tests for /auth/*: manual only.
- Tenant isolation tests under JWT for /users and /roles (F2 covers /organizations/me only).
- Full transaction lifecycle tests: cleanup failure, commit failure, rollback failure, connection close on each path.
- Extend scripts/state_check.py to check:
  - auth_session.refresh_tokens (table exists, count, active=0)
  - auth_session.get_user_status (EXECUTE ACL, behavior)
  - auth_private.credentials (count, no hash leaked)

Priority 10 — Hygiene and deprecations (CLOSED on 2026-11-13)
- Add .gitattributes to formalize the LF/CRLF policy.
- Migrate @app.on_event("startup") to lifespan= in app/main.py.
- Evaluate removal of get_tenant_context (dead code) after confirming no test or internal caller uses it.
- Migrate init_vault_key() to a separate administrative path (out of the runtime API).

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
- Do not rerun the global SECURITY DEFINER inventory.
- Do not assume the 25 pgsodium routines are application-defined functions.
- Do not assume that a function being executable only by securebiz_owner proves that an administrative invocation mechanism exists.
- Do not grant public-key administration or purge functions to runtime roles without a dedicated security design.
- Do not treat function EXECUTE ACLs as a complete analysis of indirect execution paths.
- Do not assume that the current transaction cleanup has been exhaustively tested.
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

v13 pitfalls (unchanged):
- Do not use client.cookies.set() with httpx.ASGITransport. Cookies are stored but not injected in subsequent requests. Use headers={"Cookie": f"refresh_token={token}"} for replay tests.
- Do not assume TestClient works out of the box. Starlette 1.10.0 TestClient requires httpx2. Installing httpx2 is needed if TestClient is used.
- Do not check $LASTEXITCODE after docker exec psql UPDATE or docker cp.
- Do not run a script with $ErrorActionPreference = "Stop" if it calls docker exec / docker cp.
- Do not assume psql -t -A with RETURNING returns a single line.
- Do not use 'inactive' for user status.
- Do not execute fragments of function Invoke-BlockX { ... }.
- Do not confuse docker compose build api with a config change.
- Do not assume PyPI timeouts are permanent.
- Do not use RefreshTokenError for DB failures.
- Do not remove the advisory lock on family_id.
- Do not call cleanup_context() after a rollback.
- Do not assume get_current_user maps all exceptions to 503.
- Do not assume get_authenticated_tenant_context maps all psycopg.Error to 503.
- Do not log the token, the secret, the password hash, the user_id, or the jti in authentication logs.
- Do not use cookies.set() to simulate replay.

v14.1 pitfalls (new in Priority 8):
- Do not assume the .env POSTGRES_PASSWORD matches the PostgreSQL role
  password. They can diverge (e.g., after a manual ALTER ROLE that did not
  update .env). Always verify with a SCRAM connection test from
  securebiz-api (psycopg, host='db', port=5432), not via socket Unix
  (trust).
- Do not use Get-Content -Raw + -replace + WriteAllText to rewrite .env.
  The combination can leave the file in an inconsistent state (wrong line
  endings, duplicated entries). Use [System.IO.File]::ReadAllText +
  [regex]::Split + manual reconstruction + WriteAllText, and verify the
  round-trip (exact match, single occurrence).
- Do not use Get-Random to generate a JWT secret. Use
  RandomNumberGenerator (PowerShell) or secrets.token_hex (Python).
- Do not assume Vault dev mode persists secrets across restarts. It does
  not (inmem storage). Re-provisioning is manual.
- Do not assume Docker-internal DNS names (vault:8200, db:5432) are
  reachable from the Windows host. They are only reachable from inside the
  Docker network. Scripts must be executed inside securebiz-api.
- Do not use provisioner-script token for the bootstrap
  (set_provisioner_password.py). Use the root token for the one-shot
  bootstrap, and provisioner-script only for recurring provisioning.
- Do not use email domains that are reserved by RFC 6762 (e.g., .local) in
  test users. email-validator (used by LoginRequest with EmailStr) rejects
  them. Use example.com (RFC 2606) for tests.
- Do not pass Vault tokens or database passwords via docker exec -e in
  production. Use mounted files or a secret manager. The -e approach is
  acceptable for the lab only.
- Do not assume a NOLOGIN role cannot be used. It can be activated with
  ALTER ROLE ... WITH LOGIN. The fail-closed protection is NOLOGIN, not
  PASSWORD NULL.
- Do not commit .env or .env.backup-* files. They contain secrets. Add
  them to .gitignore if not already present.

v14.2 pitfalls (new in Priority 9):
- `tests/conftest.py` must set `VAULT_TOKEN` (and `VAULT_ADDR`) before
  any `app.*` import. `app/core/vault.py` raises `RuntimeError` at
  module load (line 45) if `VAULT_TOKEN` is missing. Mocking
  `get_jwt_secret` is not enough — the import fails before the mock
  can be applied.
- `app/core/config.py` instantiates `Settings()` at module load, so
  any test that imports `app.*` must provide `DB_HOST`, `DB_PORT`,
  `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `AUTH_DB_USER`,
  `AUTH_DB_PASSWORD`. `conftest.py` does this.
- `httpx.ASGITransport` does not inject cookies set via
  `client.cookies.set()`. Use an explicit
  `headers={"Cookie": f"refresh_token={token}"}` for replay tests.
- `tests/test_isolation.py` requires the API container (`vault:8200`
  and `db:5432` are Docker-internal DNS). On the Windows host,
  3/4 tests fail (`VAULT_ADDR` unreachable). Execute in the container.
- Vault dev mode (`inmem`) regenerates the Ed25519 key on container
  restart. `auth_security.public_keys` must be updated manually
  (securebiz_user, UPDATE on `public_keys`). This is not automated.
- `scripts/state_check.py` must remain READ-ONLY, except
  `check_full_flow` which calls `install_context()` and then
  `ROLLBACK`. Do not add auto-resync of the public key inside the
  script: it would hide a real Vault restart event.
- `state_check.py` uses `_admin_ready()` to centralize degraded mode.
  When `DB_ADMIN_USER` or `DB_ADMIN_PASSWORD` is missing, all DB
  checks return SKIP (never FAIL).
- Base64 decode of the Vault public key must use `validate=True` and
  check `len(bytes) == 32`. Strict validation catches corruption.
- `psycopg3`'s `with psycopg.connect(...) as conn:` does NOT call
  `conn.close()` on context exit; it commits or rolls back. Connection
  closure happens on process exit. Do not assert `conn.close()` in
  tests; assert `conn.__exit__()` instead.
- `provision_user.py` relies on `with psycopg.connect(...)` for
  transaction management, but does not close the connection
  explicitly. A future refactor (Priority 10) should add
  `finally: conn.close()`.

Priority 10 pitfalls (new in v14.3):

- `with psycopg.connect(...) as conn:` closes the connection on context
  exit (verified with psycopg 3.3.8). Do not add a `finally: conn.close()`
  to `scripts/provision_user.py`; it would be redundant. Use
  `conn.__exit__()` in tests if you need to assert the closure.
- PowerShell 5.1 `@'...'@` here-strings and `Replace()` can fail silently
  on multi-line blocks that span CRLF/LF boundaries. Always normalize
  to LF before replacing, and normalize back to CRLF after writing.
- A relative path passed to `[System.IO.File]::ReadAllText()` is
  resolved from the .NET process working directory, not from the
  PowerShell `Get-Location`. Always use `(Resolve-Path ...).Path` or
  `Join-Path (Resolve-Path ...).Path`.
- When running a script from the project root inside the API container,
  use `docker exec -w /app securebiz-api env PYTHONPATH=/app python
  scripts/<name>.py`. Without `PYTHONPATH=/app`, the `app` package is
  not importable and you get `ModuleNotFoundError: No module named 'app'`.
- The `-w /app` and `PYTHONPATH=/app` requirement applies to all
  scripts under `scripts/` that import from `app.*` (state_check.py,
  provision_user.py, init_vault.py).
- `with psycopg.connect(...)` does NOT take a `conn.close()` call
  explicitly, but the context manager's `__exit__` closes the
  connection. Do not confuse "no explicit close" with "connection
  not closed".
- `init_vault_key()` is now `ADMIN ONLY`. Do not call it from the
  API runtime. If you need to provision Vault, run
  `scripts/init_vault.py` (admin scope).
- The API is now fail-closed: if Vault is not provisioned, requests
  that need signing return 503 with a clear error, instead of
  silently recreating a key.
- Deleting `get_tenant_context()` was safe: no route, test, or script
  referenced it. Before removing any "dead" code, always grep
  `app/`, `tests/`, and `scripts/` for the function name.
28. EXACT CONTINUATION POINT — VERSION 14.3
Version 14.3 continuation (2026-11-13):

Priority 5, Priority 6, Priority 8, Priority 9, and Priority 10 are CLOSED.

Verified state (2026-11-13):

- Tests: 132 persisted (108 host + 24 container). Files: `test_jwt.py`
  (38), `test_refresh.py` (31), `test_auth_routes.py` (18),
  `test_provision_user.py` (11), `test_dependencies_lifecycle.py` (10),
  `test_isolation.py` (4), `test_isolation_users.py` (4),
  `test_isolation_roles.py` (4), `test_refresh_db.py` (12).
- `scripts/state_check.py` v4: 10 checks, 16 records, 0 FAIL, 0 WARN,
  exit code 0.
- `scripts/init_vault.py`: new admin-only Vault provisioning script.
  Must be run once before starting the API, and again after any Vault
  restart in -dev mode (inmem storage loses all keys). Requires
  `-w /app` + `PYTHONPATH=/app` when invoked via `docker exec`.
- `auth_security.public_keys`: resynced to Vault current key
  (`757147f3...`) after 2026-11-12 Vault restart.
- `auth_session.refresh_tokens`: 42 rows, 2 active (residual from
  earlier tests, left untouched by `test_refresh_db.py`).
- `auth_private.credentials`: 1 row (test credential, Argon2id).
- `.gitignore`: `.env`, `.env.backup-*`, `__pycache__/`, `*.py[cod]`,
  `.venv/`, `venv/`, `.pytest_cache/`, `.coverage`, `*.bak`, `*.bak-*`.
- `.gitattributes`: LF/CRLF normalization, PowerShell CRLF, binary files.

Git state:

- HEAD: `3a8f2a5` (docs v0.6.0, update ROADMAP).
- `origin/main` aligned.
- Working tree clean (before this documentation update).
- 21 commits total.

Immediate next step: Phase 7 (DevSecOps and Demonstration).

- CI pipeline (GitHub Actions).
- Automated tests on every change.
- Security checks in the pipeline (SAST, DAST, dependency scanning).
- Operations documentation.
- Reproducible demonstration scenarios.
- Final security report of the lab.

Residual items for v15:

- Vault persistent backend (file, Consul) or automated re-provisioning.
- Store `provisioner-script` token in a local file (not in memory).
- Automate Vault/PG public key synchronization after Vault restart.

Do not restart the project.
Do not repeat completed inspections.
Do not weaken security to pass tests.
Do not assume Vault secrets persist. They do not (inmem).
Do not assume the public key is in sync after a Vault restart.
Preserve all existing data, Docker volumes, database security
boundaries and unrelated containers.

Priority 5 and Priority 6 are CLOSED. All functional tests passed on 12 November 2026:
- Priority 5: P1-P8 (8/8) and P11 (1/1).
- Priority 6: F2 (4/4).

Verified DB state (after tests and cleanup):
- auth_private.credentials : 1 row (test credential, Argon2id, test-user@test.com)
- auth_session.refresh_tokens : 11 rows, 0 active
- public.users : 1 row (status = active)
- public.memberships : 1 row (active, user in org 1a40e607-b991-4b06-ad1f-13106d65b12a)

Verified API state:
- securebiz-api container: running from the rebuilt image (sha256:3c0514b0...).
- /openapi.json: 8 paths.
- Packages in image: jwt 2.10.1, argon2 25.1.0, email-validator 2.2.0, httpx 0.28.1.
- Stale files: none remain.

Verified git state:
- 4 commits: 2362024, 158aeb4, ff7d60a, a65f27b.
- HEAD -> main and origin/main both on a65f27b.
- Working tree clean.

The immediate next operation is Priority 8 (provisioning endpoint or script for Argon2id hashes). Priority 6 is closed, no rebuild is pending, no commit is pending.

The first sub-step of Priority 8 is a design decision, not a code change:
- Endpoint (POST /admin/users) or script (scripts/provision_user.py)?
- Who can invoke it? (No admin role defined yet.)
- How does the plaintext password reach the provisioner? (Manual entry, or generated, or SMTP invite flow?)

Do not start Priority 8 code before these three decisions are documented.

After Priority 8, Priority 9 (extended tests and state_check extension) and Priority 10 (hygiene and deprecations) follow.

Do not restart the project.
Do not repeat completed inspections.
Do not reproduce Version 13 as if Priority 5 and Priority 6 were not implemented.
Do not invent implementation details.
Do not weaken security to pass tests.
Do not assume the rebuild is pending. It is done.

Immediate next step: document the three Priority 8 design decisions before any code change.

Preserve all existing data, Docker volumes, database security boundaries and unrelated containers.

29. FINAL HANDOVER RULE

Continue SecureBiz Lab from this exact Version 14.3 state.

The project has completed Priority 5 (Authentication and Session
Management), Priority 6 (IAM route migration to JWT, isolation test
migration), and Priority 8 (Argon2id provisioning: role, policy, scripts,
end-to-end test). All functional tests passed on 12 November 2026:
P1-P8, P11, F2, and the Priority 8 end-to-end test. The image has been
rebuilt and the container runs from the rebuilt image. Priority 5,
Priority 6, and Priority 8 are committed and pushed. Vault was restarted
and all secrets were re-provisioned; the securebiz_user password was
reset to 48 chars.

The next phase is Priority 9 (extended tests and state_check extension).

Do not restart the project.
Do not repeat completed inspections.
Do not reproduce Version 13 as if Priority 5 and Priority 6 were not
implemented.
Do not reproduce Version 14 as if Priority 8 were not implemented.
Do not invent implementation details.
Do not weaken security to pass tests.
Do not assume the rebuild is pending. It is done.
Do not assume Vault secrets persist. They do not (inmem).

Priority 9 (2026-11-13) completed the test suite (102 tests) and
extended `scripts/state_check.py` to v4 (10 checks). All Priority 9
commits are pushed to `origin/main`.

Priority 5, 6, 8, and 9 are closed.

The next phase is Priority 10 (hygiene and deprecations).
Priority 10 (2026-11-13) closed the hygiene and deprecation items
(.gitattributes, .gitignore, lifespan, HTTP 422, dead code removal,
init_vault separation). The test suite now has 132 tests
(108 host + 24 container).

Priority 5, 6, 8, 9, and 10 are closed.

The next phase is Phase 7 (DevSecOps and Demonstration).
Preserve all existing data, Docker volumes, database security boundaries
and unrelated containers.
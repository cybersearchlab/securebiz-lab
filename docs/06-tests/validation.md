# Verifications and Validation Evidence

## Completed Manual Tests

The following verifications were successfully executed during development. They are documented here as **proof of work** and are **reproducible**.

---

## v0.4.0 — Priority 5: Authentication and Session Management (2026-11-12)

### 6. Vault KV-v2 JWT Secret Provisioning

**Vault KV-v2 engine**: enabled at `secret/`.
**Secret**: stored at `secret/data/securebiz/jwt` with `current`, `current_kid`, `previous`, `previous_kid`.
**Metadata only (no secret value displayed)**:

```powershell
docker exec -e VAULT_TOKEN=dev-only-root-token securebiz-vault vault kv metadata get secret/securebiz/jwt
# Result: current_version=3 (versions 1 and 2 destroyed after exposure, version 3 active)
#         current_kid=v2 (cosmetic, due to a double rotation)

7. JWT Module — 18/18 Tests Passed
Module: app/core/jwt.py.
Test method: temporary test file (removed after execution), 3 positive + 15 negative cases.

Test	Result
P1 create + verify, sub matches	OK
P2 all required claims present	OK
P3 header alg=HS256, kid=v2	OK
N1 empty token	OK
N2 truncated token	OK
N3 tampered signature	OK
N4 unknown kid	OK
N5 alg=none	OK
N6 alg=RS256	OK
N7 wrong aud	OK
N8 wrong iss	OK
N9 expired	OK
N10 token_type=refresh	OK
N11 sub non-UUID	OK
N12 jti non-UUID	OK
N13 sub uppercase	OK
N14 missing jti	OK
N15 create with non-canonical UUID	OK
Result: 18 passed, 0 failed.

8. Authentication Functional Tests — 9/9 Passed
Run 1 — Bloc E2 v7 (P1–P8), Run ID ac649048:

Test	Result
P1 login OK (200 + access_token + refresh cookie)	OK
P2 unknown email (401 Invalid credentials.)	OK
P3 wrong password (401 Invalid credentials.)	OK
P4 refresh rotation (200 + new cookie, same family_id)	OK
P5 replay of old cookie (401 + F1 fully revoked)	OK
P6 new login (200 + F2 distinct from F1)	OK
P7 logout (200 + F2 revoked)	OK
P8 logout without cookie (200)	OK
SQL verification after run:

sql
SELECT count(*) FROM auth_session.refresh_tokens WHERE family_id IN (F1, F2) AND revoked_at IS NULL;
-- Result: 0 (both families fully revoked)
SELECT count(*) FROM auth_session.refresh_tokens WHERE revoked_at IS NULL;
-- Result: 0 (no active token left in the database)
Run 2 — Bloc E2 bis v4 (P11), Run ID 89fe8258:

Test	Result
P11 login (200, family F3 created)	OK
P11 disable user (status='disabled')	OK (SELECT verified)
P11 refresh with disabled user (401)	OK
P11 F3 fully revoked (0 active)	OK
P11 user reactivated (status='active')	OK (SELECT verified)
Final database state after Priority 5:

sql
SELECT 'credentials=' || (SELECT count(*) FROM auth_private.credentials)
    || ' refresh_tokens=' || (SELECT count(*) FROM auth_session.refresh_tokens)
    || ' active_tokens=' || (SELECT count(*) FROM auth_session.refresh_tokens WHERE revoked_at IS NULL)
    || ' user=' || (SELECT status FROM public.users WHERE id = 'a2c643f2-7212-4693-bc7f-d220cb9cdaf4'::uuid);
-- Result: credentials=1 refresh_tokens=0 active_tokens=0 user=active
9. API Surface After Priority 5
powershell
docker exec securebiz-api python -c "import json, urllib.request; data = json.loads(urllib.request.urlopen('http://localhost:8000/openapi.json', timeout=10).read()); print('Total paths:', len(data['paths'])); [print(' ', p) for p in sorted(data['paths'].keys())]"
Result: 8 paths:

text
/
/health
/organizations/me
/roles
/users
/auth/login
/auth/refresh
/auth/logout
10. Docker Image Rebuild — Package Persistence
Build: docker compose build api with --timeout 120 --retries 5 and Aliyun PyPI mirror. Build time: ~30 min (slow mirror but successful).

Package verification after container recreate (proving persistence in the image, not just in the container layer):

powershell
docker compose up -d --force-recreate api
docker exec securebiz-api python -c "import jwt, argon2, email_validator, httpx; print('PyJWT', jwt.__version__); print('argon2-cffi', argon2.__version__); print('email-validator', email_validator.__version__); print('httpx', httpx.__version__)"
# Result: PyJWT 2.10.1
#         argon2-cffi 25.1.0
#         email-validator 2.2.0
#         httpx 0.28.1
Second recreate (to prove persistence):

powershell
docker compose up -d --force-recreate api
docker exec securebiz-api python -c "import jwt; print('PyJWT', jwt.__version__)"
# Result: PyJWT 2.10.1 (still present after second recreate)
Conclusion: the Priority 5 packages are now persisted in the securebiz-lab-api:latest image. A container restart no longer loses them.

11. End-to-End Login After Rebuild
powershell
docker exec securebiz-api python -c "
import asyncio
from httpx import ASGITransport, AsyncClient
from app.main import app

async def test():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='https://testserver') as client:
        r = await client.post('/auth/login', json={'email': 'test-user@test.com', 'password': 'TestPassword!2026'})
        print('Login status:', r.status_code)
        print('Has access_token:', 'access_token' in r.json())
        print('Has refresh cookie:', 'refresh_token' in client.cookies)

asyncio.run(test())
"
Result:

text
Login status: 200
Has access_token: True
Has refresh cookie: True
12. Test Configuration Used
Test user: test-user@test.com / TestPassword!2026 (test credential only, Argon2id, manually inserted in auth_private.credentials via psql as securebiz_user).

Test organization: 1a40e607-b991-4b06-ad1f-13106d65b12a.

Test user ID: a2c643f2-7212-4693-bc7f-d220cb9cdaf4.

HTTP client: httpx.AsyncClient with ASGITransport(app=app) and base_url="https://testserver".

Cookie handling: headers={"Cookie": f"refresh_token={token}"} for replay tests. httpx.ASGITransport does not inject cookies set via cookies.set().

All temporary test files removed after execution.

All test families (F1, F2, F3) deleted from the database after verification.

13. Known Limitations Specific to Testing
httpx.ASGITransport does not inject cookies set via cookies.set(). Tests must use explicit Cookie header for replay scenarios.

TestClient of Starlette 1.10.0 requires httpx2 (separate package from httpx). httpx2 was installed for compatibility.

$LASTEXITCODE in PowerShell is unreliable for docker exec psql and docker cp when stderr is written. Verified by SELECT queries instead.

psql -t -A with RETURNING returns two lines (value + INSERT 0 N). Parsed with regex.

users_status_check allows only 'active', 'disabled', 'pending'. 'inactive' is rejected. The P11 test uses 'disabled'.

v0.3.0 — Cryptographic Architecture
1. Infrastructure & Configuration (v0.1.0 → v0.2.0)
Infrastructure Startup: Successful launch of all services using docker compose up -d --build.

Container Status: Presence of the API, PostgreSQL, and Vault containers using docker compose ps.

Base API Route: Successful response from GET / (version 0.2.0).

Health Check: Healthy response from GET /health, confirming PostgreSQL connection and execution of SELECT 1.

Strict Configuration Validation: Negative test executed via docker compose run --rm -e DB_USER= api. The API correctly refused to start, raising a ValidationError: string_too_short. This proves the fail-fast mechanism prevents starting with empty credentials.

2. Vault & pgsodium Initialization (v0.3.0)
Vault Initialization: API startup logs confirm the initialization of the Transit engine and the successful creation (or presence) of the securebiz-context Ed25519 key.

pgsodium Installation: The custom PostgreSQL image was built successfully. Verified via:

sql
SELECT extname FROM pg_extension WHERE extname='pgsodium';
-- Result: pgsodium 3.1.9
Ed25519 Function Availability: The function pgsodium.crypto_sign_verify_detached(bytea, bytea, bytea) is present. Verified via:

sql
SELECT to_regprocedure('pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)');
-- Result: pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)
Ed25519 Execution Test: A dummy signature (all zeros) is correctly rejected:

sql
SELECT pgsodium.crypto_sign_verify_detached(
    decode(repeat('00', 64), 'hex'),
    convert_to('test', 'UTF8'),
    decode(repeat('00', 32), 'hex')
);
-- Result: f (false)
3. Public Key Registration (v0.3.0)
Vault Public Key Retrieved: The Ed25519 public key is exposed by Vault Transit:

Base64: 3kvLcWbnR3YoCRyvZGkBqziKM9CtqcATfzAF8k4QCSsk=

Hex: ccc071be49abbcdef22b541bb7ad984de1364730814dde3d54b9844a370a4e89

Length: 32 bytes

Public Key Registered in PostgreSQL: Via securebiz_register_public_key():

sql
SELECT kid, octet_length(public_key), encode(public_key, 'hex')
FROM auth_security.public_keys;
-- Result: securebiz-context | 32 | ccc071be...
Independent Cryptographic Verification: The Vault signature was verified independently with the cryptography Python library (Ed25519PublicKey.verify()), confirming that Vault's output is a valid Ed25519 signature compatible with the registered public key.

4. End-to-End Cryptographic Flow (v0.3.0) — Ultimate proof
Full flow validated with securebiz_app:

Payload signed by Vault (claims: iss=securebiz-api, aud=securebiz-postgres, sub=<user>, org=<org>, iat, exp, jti).

64-byte Ed25519 signature verified by pgsodium.crypto_sign_verify_detached().

securebiz_install_context(payload, signature, kid) returned True.

securebiz_get_context('user_id') returned the correct UUID.

securebiz_get_context('organization_id') returned the correct UUID.

Transaction rolled back cleanly (no test data persisted).

Output observed:

text
Payload: {"iss":"securebiz-api","aud":"securebiz-postgres","sub":"a2c643f2-...","org":"1a40e607-...","iat":1794316547,"exp":1794316607,"jti":"2c117f52-..."}
Signature length: 64 bytes
install_context returned: True
Context user_id: a2c643f2-7212-4693-bc7f-d220cb9cdaf4
Context org_id: 1a40e607-b991-4b06-ad1f-13106d65b12a
SUCCESS: Full cryptographic flow verified!
Transaction rolled back (test data not persisted).
5. RLS & RBAC Policy Verification (v0.3.0)
RLS enabled and forced on all tenant-scoped tables:

sql
SELECT relname, relrowsecurity, relforcerowsecurity
FROM pg_class
WHERE relname IN ('organizations','users','memberships','roles','membership_roles','role_permissions');
-- All rows: t | t
FOR SHARE lock test with securebiz_owner:

sql
SET LOCAL ROLE securebiz_owner;
SELECT ... FROM users JOIN memberships JOIN organizations FOR SHARE OF u, m, o;
-- Result: 1 row (user + org + statuses)
This required targeted UPDATE(column) grants (users.id, memberships.user_id, organizations.id), which were added.

Role privilege audit:

Role	rolsuper	rolbypassrls	rolcanlogin
securebiz_owner	f	f	f
securebiz_app	f	f	t
securebiz_auth	f	f	t
Control Commands
Use these commands to verify the current state of the infrastructure:

powershell
# Container status
docker compose ps

# API base route
Invoke-RestMethod http://localhost:8000/

# API health
Invoke-RestMethod http://localhost:8000/health

# API OpenAPI paths (expected: 8)
docker exec securebiz-api python -c "import json, urllib.request; data = json.loads(urllib.request.urlopen('http://localhost:8000/openapi.json', timeout=10).read()); print('Total paths:', len(data['paths']))"

# JWT secret (metadata only, not the secret)
docker exec -e VAULT_TOKEN=dev-only-root-token securebiz-vault vault kv metadata get secret/securebiz/jwt

# pgsodium installation
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT extname, extversion FROM pg_extension WHERE extname='pgsodium';"

# Ed25519 function presence
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT to_regprocedure('pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)');"

# Registered public key
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT kid, octet_length(public_key) FROM auth_security.public_keys;"

# RLS status
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('organizations','users','memberships','roles');"

# Authentication state (no secrets)
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -t -A -c "SELECT 'credentials=' || (SELECT count(*) FROM auth_private.credentials) || ' refresh_tokens=' || (SELECT count(*) FROM auth_session.refresh_tokens) || ' active_tokens=' || (SELECT count(*) FROM auth_session.refresh_tokens WHERE revoked_at IS NULL);"

# Packages in image
docker exec securebiz-api python -c "import jwt, argon2, email_validator, httpx; print('PyJWT', jwt.__version__, '| argon2-cffi', argon2.__version__, '| email-validator', email_validator.__version__, '| httpx', httpx.__version__)"
To inspect the logs:

powershell
docker compose logs --tail 100 api
docker compose logs --tail 100 db
docker compose logs --tail 100 vault
Automated Tests to Add (Roadmap)
Unit tests for app/core/jwt.py (18/18 already passed manually; migrate to tests/).

Unit tests for app/services/refresh.py (P1–P8 + P11 already passed manually; migrate to tests/).

Integration tests for /auth/login, /auth/refresh, /auth/logout.

API tests using httpx.AsyncClient with ASGITransport (not TestClient, which requires httpx2).

Tenant isolation tests under JWT (after IAM routes migration to get_authenticated_tenant_context()).

Cryptographic tests: rejection of a tampered Ed25519 signature by pgsodium.

Cryptographic tests: rejection of an expired exp claim.

Cryptographic tests: rejection of a reused jti (anti-replay).

RLS tests executed specifically with the securebiz_app role.

Migration tests (from an empty database and from a previous version).

Non-regression tests for errors and HTTP responses.

Extension of scripts/state_check.py to cover auth_session.refresh_tokens, get_user_status, auth_private.credentials.

Evidence to Preserve
For each development step, the following must be preserved:

The date and the relevant Git commit.

The exact command executed.

The relevant output or screenshot.

The environment versions (docker --version, python --version, etc.).

Any known deviations or limitations.

Security Rule: Systematically mask passwords, tokens, keys, connection strings, and personal data before saving evidence in the repository.
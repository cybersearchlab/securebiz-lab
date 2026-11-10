# Verifications and Validation Evidence

## Completed Manual Tests

The following verifications were successfully executed during development. They are documented here as **proof of work** and are **reproducible**.

### 1. Infrastructure & Configuration (v0.1.0 → v0.2.0)

1.  **Infrastructure Startup**: Successful launch of all services using `docker compose up -d --build`.
2.  **Container Status**: Presence of the API, PostgreSQL, and Vault containers using `docker compose ps`.
3.  **Base API Route**: Successful response from `GET /` (version 0.2.0).
4.  **Health Check**: Healthy response from `GET /health`, confirming PostgreSQL connection and execution of `SELECT 1`.
5.  **Strict Configuration Validation**: Negative test executed via `docker compose run --rm -e DB_USER= api`. The API correctly refused to start, raising a `ValidationError: string_too_short`. This proves the fail-fast mechanism prevents starting with empty credentials.

### 2. Vault & pgsodium Initialization (v0.3.0)

6.  **Vault Initialization**: API startup logs confirm the initialization of the Transit engine and the successful creation (or presence) of the `securebiz-context` Ed25519 key.
7.  **pgsodium Installation**: The custom PostgreSQL image was built successfully. Verified via:
    ```sql
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
Note: These are manual validations. They will be supplemented by automated Pytest tests in the upcoming phases. The evidence for each test is reproducible via the commands in docs/03-installation/setup.md and the SQL scripts in database/migrations/.

Control Commands
Use these commands to verify the current state of the infrastructure:

powershell
# Container status
docker compose ps

# API base route
Invoke-RestMethod http://localhost:8000/

# API health
Invoke-RestMethod http://localhost:8000/health

# pgsodium installation
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT extname, extversion FROM pg_extension WHERE extname='pgsodium';"

# Ed25519 function presence
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT to_regprocedure('pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)');"

# Registered public key
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT kid, octet_length(public_key) FROM auth_security.public_keys;"

# RLS status
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -c "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname IN ('organizations','users','memberships','roles');"
To inspect the logs:

powershell
docker compose logs --tail 100 api
docker compose logs --tail 100 db
docker compose logs --tail 100 vault
Automated Tests to Add (Roadmap)
Unit tests for services and schemas.

API tests using FastAPI TestClient or an equivalent HTTP client.

PostgreSQL integration tests.

Authentication and authorization tests.

Isolation tests between two organizations (A and B).

Cryptographic tests: rejection of a tampered Ed25519 signature by pgsodium.

Cryptographic tests: rejection of an expired exp claim.

Cryptographic tests: rejection of a reused jti (anti-replay).

RLS tests executed specifically with the securebiz_app role.

Migration tests (from an empty database and from a previous version).

Non-regression tests for errors and HTTP responses.

Evidence to Preserve
For each development step, the following must be preserved:

The date and the relevant Git commit.

The exact command executed.

The relevant output or screenshot.

The environment versions (docker --version, python --version, etc.).

Any known deviations or limitations.

Security Rule: Systematically mask passwords, tokens, keys, connection strings, and personal data before saving evidence in the repository.
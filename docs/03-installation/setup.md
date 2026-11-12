To view the logs:

powershell
docker compose logs --tail 100 api
docker compose logs --tail 100 db
docker compose logs --tail 100 vault
Verify the API:

powershell
Invoke-RestMethod http://localhost:8000/
Invoke-RestMethod http://localhost:8000/health
The root route should return application information. The /health route
must confirm database connectivity (healthy / available / connected).

Verify the API surface (v0.4.0):

powershell
docker exec securebiz-api python -c "import json, urllib.request; data = json.loads(urllib.request.urlopen('http://localhost:8000/openapi.json', timeout=10).read()); print('Total paths:', len(data['paths']))"
# Expected: Total paths: 8
If the count is less than 8, the API is running an older main.py. Restart:

powershell
docker compose restart securebiz-api
Applying the Migrations
Two migrations have been applied to the development database:

001_iam_multitenant_v8.sql — IAM schema, RLS, RBAC functions.

002_auth_session.sql — auth_session schema, refresh_tokens table, get_user_status function.

If you need to recreate them from scratch:

powershell
# Copy the migration into the container
docker cp database/migrations/001_iam_multitenant_v8.sql securebiz-postgres:/tmp/v1.sql
docker cp database/migrations/002_auth_session.sql securebiz-postgres:/tmp/v2.sql

# Apply them with the migration admin account
docker exec -it securebiz-postgres psql -v ON_ERROR_STOP=1 -U securebiz_user -d securebiz -f /tmp/v1.sql
docker exec -it securebiz-postgres psql -v ON_ERROR_STOP=1 -U securebiz_user -d securebiz -f /tmp/v2.sql
Important: The migration 001 includes ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE; to avoid a pgsodium event trigger conflict (see CHANGELOG.md v0.3.0, "Fixed").

Migration 002 content:

Creates auth_session schema.

Creates auth_session.refresh_tokens (BYTEA hash, family_id, revoked_at, replaced_by, CHECK 32 bytes, CHECK expires_at > issued_at, UNIQUE token_hash).

Creates 3 indexes on user_id, family_id, expires_at.

Creates auth_session.get_user_status(UUID) (SECURITY DEFINER, owned by securebiz_owner).

Grants securebiz_auth SELECT, INSERT, UPDATE on refresh_tokens (no DELETE).

Grants securebiz_auth EXECUTE on get_user_status.

Revokes all from securebiz_app and PUBLIC.

Registering the Vault Public Key
After the migration, the Ed25519 public key from Vault must be registered
in auth_security.public_keys. In development, the key changes every
time the Vault container is recreated.

The exact procedure is documented in docs/06-tests/verifications.md §3.

Provisioning the JWT Secret in Vault KV-v2 (v0.4.0)
The JWT HS256 secret must be provisioned in Vault KV-v2 at secret/data/securebiz/jwt. The secret is a 32-byte value (64 hex chars), never displayed.

Read-only inspection:

powershell
docker exec -e VAULT_TOKEN=dev-only-root-token securebiz-vault vault secrets list
docker exec -e VAULT_TOKEN=dev-only-root-token securebiz-vault vault kv metadata get secret/securebiz/jwt
If the secret does not exist, provision it:

powershell
# Generate 32 bytes (64 hex chars), no display
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$jwtSecret = -join ($bytes | ForEach-Object { $_.ToString('x2') })

$payload = @{
    current     = $jwtSecret
    current_kid = "v1"
    previous    = ""
    previous_kid = ""
} | ConvertTo-Json -Compress

$payload | docker exec -i -e VAULT_TOKEN=dev-only-root-token securebiz-vault vault kv put secret/securebiz/jwt -

Remove-Variable jwtSecret, payload, bytes
Never execute vault kv get secret/securebiz/jwt without -version= — it displays the secret. Use vault kv metadata get to verify the versions.

Rotation: write a new version with current_kid=v2 and previous/previous_kid set to the old values. Destroy the old versions with vault kv destroy -versions=N. See docs/05-securite/security.md.

Creating a Test Credential (v0.4.0)
There is no provisioning endpoint yet. The only existing credential was inserted manually via psql as securebiz_user. The hash must be Argon2id with parameters time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16.

Do not commit the hash. Do not display the password.

powershell
# Generate the hash in the API container (no display of the password)
$hash = docker exec securebiz-api python -c "from argon2 import PasswordHasher; h = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16); print(h.hash('TestPassword!2026'))"

# Insert the credential for the test user
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -c "INSERT INTO auth_private.credentials (user_id, password_hash, updated_at) VALUES ('a2c643f2-7212-4693-bc7f-d220cb9cdaf4'::uuid, '$hash', clock_timestamp()) ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = clock_timestamp();"

# Verify (no hash displayed)
docker exec securebiz-postgres psql -U securebiz_user -d securebiz -t -A -c "SELECT count(*) FROM auth_private.credentials WHERE user_id = 'a2c643f2-7212-4693-bc7f-d220cb9cdaf4'::uuid;"
# Expected: 1
Security note: ON CONFLICT DO UPDATE silently overwrites an existing credential. For a real provisioning workflow, use a strict INSERT (no ON CONFLICT) and abort on conflict.

Stopping Services
powershell
docker compose down
This command preserves the named volume. Do not use docker compose down -v
unless you explicitly intend to delete persistent data.

Accessing PostgreSQL for Local Administration
The command used for administration is:

powershell
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz
Note: The database name securebiz and the container name are those
observed during the working session. Check the Compose file and environment
if these values change.

Accessing the API Container
powershell
docker exec -it securebiz-api bash
# or a one-off command
docker exec securebiz-api python -c "import jwt; print(jwt.__version__)"
The API container has the Priority 5 packages persisted in the image (PyJWT 2.10.1, argon2-cffi 25.1.0, email-validator 2.2.0, httpx 0.28.1). If any is missing, the image was not rebuilt after a requirements.txt change: docker compose build api && docker compose up -d --force-recreate api.

Initial Troubleshooting
API fails to start
Check docker compose logs api. If you see
a ValidationError from Pydantic, a required environment variable
is missing or empty in docker-compose.yml.

PostgreSQL is not ready
Check docker compose logs db and docker compose ps.

/health returns 503
Check the DB service status and connection variables (without exposing secrets).

Vault is unreachable
Check docker compose logs vault and ensure the Vault container is healthy.

Invalid Ed25519 signature
The public key in auth_security.public_keys does not match the current Vault private key (likely after a Vault container restart). Re-register the new public key (see docs/06-tests/verifications.md §3).

Permission denied for table users
If securebiz_owner cannot read users despite the owner_users_policy, verify that the targeted UPDATE(column) grants have been applied (see CHANGELOG.md v0.3.0).

Python code changes
Rebuild the service if necessary with docker compose up --build -d.

docker compose build api times out on PyPI (v0.4.0)
The Dockerfile has --timeout 120 --retries 5 and the Aliyun mirror. If the build still fails, the cause is usually one of:

PyPI / Aliyun mirror is slow. Retry. If it consistently fails on psycopg-binary or cryptography (large files), use the pre-download approach: download the wheels on the host, copy them into the build context, and use pip install --no-index --find-links.

Docker bridge MTU too high. If small packages succeed but large ones (5+ MB) time out, the MTU is likely the cause. Fix: add to docker-compose.yml:

yaml
networks:
  default:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: 1400
Then docker compose down && docker compose up -d && docker compose build api.

ModuleNotFoundError: No module named 'jwt' (or argon2, email_validator) (v0.4.0)
The container is running an image without the Priority 5 packages. Rebuild:

powershell
docker compose build api
docker compose up -d --force-recreate api
/openapi.json returns fewer than 8 paths (v0.4.0)
The API is running an older main.py in memory. Restart:

powershell
docker compose restart securebiz-api
psql writes to stderr and a PowerShell script stops (v0.4.0)
Wrap the block in try/finally and set $ErrorActionPreference = "Continue" locally. Do not check $LASTEXITCODE after psql (it is set to 1 on stderr even when the command succeeds). Verify the DB state with a SELECT instead.

docker cp writes to stderr and a PowerShell script stops (v0.4.0)
Same fix as above. docker cp writes Successfully copied to stderr. Use 2>&1 | Out-Null and verify with Test-Path.

Persistent Data
The securebiz_pgdata volume contains PostgreSQL data. Deleting a volume
is destructive. Before any maintenance operation, plan for a proper backup.

Rebuild and Cleanup
To rebuild the API image after a requirements.txt change:

powershell
docker compose build api
docker compose up -d --force-recreate api
The rebuild does not modify docker-compose.yml, Dockerfile, requirements.txt, .env, containers (except securebiz-api on --force-recreate), or volumes. Vault and PostgreSQL are not touched.

To clean up backup files (after Priority 5 is fully validated):

powershell
Remove-Item -Path .\Dockerfile.bak-pip-mirror -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path .\app -Recurse -Filter '*.bak-*' | Remove-Item -Force
Remove-Item -Path .\requirements.txt.bak-* -Force -ErrorAction SilentlyContinue
Consider adding *.bak-* and *.corrupted-* to .gitignore.

text

## Ce qui a changé vs v0.3.0

| Section | Changement |
|---|---|
| **Known Prerequisites** | Ajout `PowerShell (version 5.1 confirmed)` |
| **Configuration** | Ajout `AUTH_DB_*`, `JWT_*`, `REFRESH_TTL_DAYS`. Précision : JWT secret pas dans `.env`. |
| **Launching the Project** | Ajout vérification `Total paths: 8` + restart si moins. |
| **Applying the Migrations** | Ajout `002_auth_session.sql` + description de son contenu. `-v ON_ERROR_STOP=1` ajouté. |
| **Registering the Vault Public Key** | Inchangé (référence à `verifications.md` §3 au lieu de `validation.md`). |
| **Provisioning the JWT Secret (nouveau)** | Section complète : inspection, génération 32 bytes, `vault kv put`, rotation, destroy. |
| **Creating a Test Credential (nouveau)** | Section complète : génération Argon2id, INSERT, vérification. Note sur `ON CONFLICT DO UPDATE`. |
| **Accessing the API Container (nouveau)** | Section : `docker exec -it bash` + vérification packages. |
| **Initial Troubleshooting** | Ajout `build api` timeout PyPI/MTU, `ModuleNotFoundError`, `/openapi.json` < 8, `psql` stderr, `docker cp` stderr. |
| **Rebuild and Cleanup (nouveau)** | Section : rebuild + cleanup backups. |
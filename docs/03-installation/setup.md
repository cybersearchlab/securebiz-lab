Testing the Cryptographic Flow
The end-to-end flow (Vault → pgsodium → securebiz_install_context) can be
validated manually with a Python script executed inside the api container.
See docs/06-tests/validation.md §4 for the exact command and expected output.
Automated Pytest tests are planned.

text

---

## FICHIER 2 : `docs/03-installation/setup.md`

```markdown
# Installation and Launch

## Known Prerequisites

-   Windows 11.
-   PowerShell.
-   Docker Desktop with Docker Engine and Docker Compose.
-   Visual Studio Code or an equivalent editor.

The exact installed versions may change; check `docker --version`,
`docker compose version`, and `docker version` on your machine.

## Configuration

The project uses a `.env` file at the root for PostgreSQL configuration
variables consumed by Docker Compose. The initial configuration uses
variables such as `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`.

Additionally, the API requires the following variables (defined in
`docker-compose.yml`, not necessarily in `.env`):

- `DB_USER` (e.g., `securebiz_app`)
- `DB_PASSWORD`
- `VAULT_ADDR` (e.g., `http://vault:8200`)
- `VAULT_TOKEN` (for development only)

**Security Rule:** Never publish the contents of the `.env` file. Never
paste passwords, tokens, or secrets into tickets, screenshots, or
conversations.

## Launching the Project

From the repository root:

```powershell
# Build and start all services (API, DB, Vault)
docker compose up --build -d

# Check container status
docker compose ps
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

Applying the IAM Migration
The IAM migration database/migrations/001_iam_multitenant_v8.sql has
already been applied to the development database. If you need to recreate
it from scratch:

powershell
# Copy the migration into the container
docker cp database/migrations/001_iam_multitenant_v8.sql securebiz-postgres:/tmp/v8.sql

# Apply it with the migration admin account
docker exec -it securebiz-postgres psql -U securebiz_user -d securebiz -f /tmp/v8.sql
Important: The migration includes ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE;
to avoid a pgsodium event trigger conflict (see CHANGELOG.md v0.3.0, "Fixed").

Registering the Vault Public Key
After the migration, the Ed25519 public key from Vault must be registered
in auth_security.public_keys. In development, the key changes every
time the Vault container is recreated.

The exact procedure is documented in docs/06-tests/validation.md §3.

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

Initial Troubleshooting
API fails to start: Check docker compose logs api. If you see
a ValidationError from Pydantic, a required environment variable
is missing or empty in docker-compose.yml.

PostgreSQL is not ready: Check docker compose logs db and
docker compose ps.

/health returns 503: Check the DB service status and connection
variables (without exposing secrets).

Vault is unreachable: Check docker compose logs vault and ensure
the Vault container is healthy.

Invalid Ed25519 signature: The public key in auth_security.public_keys
does not match the current Vault private key (likely after a Vault
container restart). Re-register the new public key (see validation.md §3).

Permission denied for table users: If securebiz_owner cannot read
users despite the owner_users_policy, verify that the targeted
UPDATE(column) grants have been applied (see CHANGELOG.md v0.3.0).

Python code changes: Rebuild the service if necessary with
docker compose up --build -d.

Persistent Data
The securebiz_pgdata volume contains PostgreSQL data. Deleting a volume
is destructive. Before any maintenance operation, plan for a proper backup.
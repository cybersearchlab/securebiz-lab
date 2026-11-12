-- ============================================================================
-- SecureBiz Lab -- Migration 003
-- Provisioning role for Argon2id credential creation
-- PostgreSQL 16
--
-- IMPORTANT:
--   - Creates securebiz_provisioner with NOLOGIN.
--   - The role is activated separately after its password is stored in Vault.
--   - Only INSERT is granted on auth_private.credentials.
--   - No SELECT, UPDATE or DELETE on auth_private.credentials.
--   - No membership in other PostgreSQL roles.
--   - Never used by the API runtime.
-- ============================================================================

BEGIN;

-- 1. Dedicated provisioning role (initially disabled)
CREATE ROLE securebiz_provisioner
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    NOREPLICATION
    NOBYPASSRLS;

-- 2. Schema access
GRANT USAGE ON SCHEMA auth_private
    TO securebiz_provisioner;

-- 3. Table privilege (INSERT only)
GRANT INSERT ON TABLE auth_private.credentials
    TO securebiz_provisioner;

-- 4. Documentation
COMMENT ON ROLE securebiz_provisioner IS
    'Dedicated role for Argon2id credential provisioning. Initially NOLOGIN. Activated only after its password is securely provisioned through Vault. Has INSERT only on auth_private.credentials, with no SELECT, UPDATE or DELETE on that table. Never used by the API runtime.';

COMMIT;
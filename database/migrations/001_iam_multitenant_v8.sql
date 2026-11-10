
-- ============================================================================
-- SecureBiz Lab
-- Multi-Tenant IAM Schema and RLS Policies
-- Migration: V8 - Candidate for validation
-- PostgreSQL 16
--
-- IMPORTANT:
--   - This migration is not production-approved.
--   - It expects the three PostgreSQL roles to exist already.
--   - It refuses to overwrite existing IAM schemas or tables.
--   - It must be tested in the existing SecureBiz Lab Docker environment.
-- ============================================================================

BEGIN;

-- ============================================================================
-- 00. PREFLIGHT: ROLES, MEMBERSHIPS, EXTENSIONS AND EXISTING OBJECTS
-- ============================================================================
ALTER EVENT TRIGGER pgsodium_trg_mask_update DISABLE;

DO $preflight$
DECLARE
    v_role RECORD;
    v_executor_is_superuser BOOLEAN;
BEGIN
    SELECT rolsuper
      INTO v_executor_is_superuser
      FROM pg_catalog.pg_roles
     WHERE rolname = current_user;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unable to identify migration executor';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'securebiz_owner'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'securebiz_auth'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'securebiz_app'
    ) THEN
        RAISE EXCEPTION 'Required roles must be provisioned before V8';
    END IF;

    SELECT * INTO v_role
      FROM pg_catalog.pg_roles
     WHERE rolname = 'securebiz_owner';

    IF v_role.rolcanlogin
       OR v_role.rolsuper
       OR v_role.rolcreatedb
       OR v_role.rolcreaterole
       OR v_role.rolreplication
       OR v_role.rolbypassrls THEN
        RAISE EXCEPTION
            'securebiz_owner must be NOLOGIN and have no administrative attributes';
    END IF;

    -- Reject inherited membership in privileged roles.
    FOR v_role IN
        SELECT *
          FROM pg_catalog.pg_roles
         WHERE rolname IN ('securebiz_owner', 'securebiz_auth', 'securebiz_app')
    LOOP
        IF EXISTS (
            SELECT 1
              FROM pg_catalog.pg_roles AS privileged_role
             WHERE (
                    privileged_role.rolsuper
                 OR privileged_role.rolcreatedb
                 OR privileged_role.rolcreaterole
                 OR privileged_role.rolreplication
                 OR privileged_role.rolbypassrls
                 OR privileged_role.rolname IN (
                     'pg_read_all_data',
                     'pg_write_all_data',
                     'pg_read_server_files',
                     'pg_write_server_files',
                     'pg_execute_server_program',
                     'pg_signal_backend',
                     'pg_monitor',
                     'pg_checkpoint',
                     'pg_create_subscription'
                 )
             )
               AND pg_catalog.pg_has_role(
                    v_role.rolname,
                    privileged_role.rolname,
                    'MEMBER'
               )
        ) THEN
            RAISE EXCEPTION
                'Role % inherits membership in a privileged role',
                v_role.rolname;
        END IF;
    END LOOP;

    IF pg_catalog.pg_has_role(
        'securebiz_app', 'securebiz_owner', 'MEMBER'
    ) OR pg_catalog.pg_has_role(
        'securebiz_auth', 'securebiz_owner', 'MEMBER'
    ) THEN
        RAISE EXCEPTION
            'Application and authentication roles must not be members of securebiz_owner';
    END IF;

    FOR v_role IN
        SELECT *
          FROM pg_catalog.pg_roles
         WHERE rolname IN ('securebiz_app', 'securebiz_auth')
    LOOP
        IF NOT v_role.rolcanlogin
           OR v_role.rolsuper
           OR v_role.rolcreatedb
           OR v_role.rolcreaterole
           OR v_role.rolreplication
           OR v_role.rolbypassrls THEN
            RAISE EXCEPTION
                'Role % must be LOGIN without administrative attributes',
                v_role.rolname;
        END IF;
    END LOOP;

    IF NOT v_executor_is_superuser
       AND NOT pg_catalog.pg_has_role(
            current_user, 'securebiz_owner', 'MEMBER'
       ) THEN
        RAISE EXCEPTION
            'Migration executor must be superuser or a member of securebiz_owner';
    END IF;

    IF pg_catalog.to_regnamespace('pgsodium') IS NULL
       OR pg_catalog.to_regprocedure(
            'pgsodium.crypto_sign_verify_detached(bytea,bytea,bytea)'
       ) IS NULL THEN
        RAISE EXCEPTION
            'pgsodium Ed25519 verification function is unavailable';
    END IF;

    IF pg_catalog.to_regnamespace('auth_security') IS NOT NULL
       OR pg_catalog.to_regnamespace('auth_private') IS NOT NULL THEN
        RAISE EXCEPTION
            'IAM schemas already exist; V8 will not overwrite them';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
           AND c.relname IN (
               'organizations',
               'users',
               'memberships',
               'roles',
               'permissions',
               'membership_roles',
               'role_permissions'
           )
    ) THEN
        RAISE EXCEPTION
            'One or more IAM business objects already exist in public';
    END IF;
END;
$preflight$;

-- ============================================================================
-- 01. SCHEMAS AND INITIAL PRIVILEGES
-- ============================================================================

CREATE SCHEMA auth_security;
CREATE SCHEMA auth_private;

REVOKE ALL ON SCHEMA auth_security FROM PUBLIC;
REVOKE ALL ON SCHEMA auth_private FROM PUBLIC;

GRANT USAGE ON SCHEMA public
    TO securebiz_app, securebiz_owner;

GRANT USAGE ON SCHEMA auth_security
    TO securebiz_app, securebiz_owner;

GRANT USAGE ON SCHEMA auth_private
    TO securebiz_auth, securebiz_owner;

GRANT USAGE ON SCHEMA pgsodium
    TO securebiz_owner;

-- Temporary CREATE privilege is needed to transfer function ownership.
GRANT CREATE ON SCHEMA auth_security, auth_private
    TO securebiz_owner;

-- ============================================================================
-- 02. BUSINESS TABLES
-- ============================================================================

CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(150) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX organizations_slug_lower_unique
    ON public.organizations (lower(slug));

CREATE TABLE public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX users_email_lower_unique
    ON public.users (lower(email));

CREATE TABLE auth_private.credentials (
    user_id UUID PRIMARY KEY
        REFERENCES public.users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE public.memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL
        REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL
        REFERENCES public.users(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'invited', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT memberships_user_org_unique
        UNIQUE (organization_id, user_id),

    CONSTRAINT memberships_id_org_unique
        UNIQUE (id, organization_id)
);

CREATE INDEX memberships_user_id_idx
    ON public.memberships (user_id);

CREATE TABLE public.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL
        REFERENCES public.organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT roles_id_org_unique
        UNIQUE (id, organization_id)
);

CREATE UNIQUE INDEX roles_org_name_lower_unique
    ON public.roles (organization_id, lower(name));

CREATE TABLE public.permissions (
    code VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL
);

CREATE TABLE public.membership_roles (
    organization_id UUID NOT NULL,
    membership_id UUID NOT NULL,
    role_id UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    PRIMARY KEY (membership_id, role_id),

    CONSTRAINT membership_roles_membership_fk
        FOREIGN KEY (membership_id, organization_id)
        REFERENCES public.memberships (id, organization_id)
        ON DELETE CASCADE,

    CONSTRAINT membership_roles_role_fk
        FOREIGN KEY (role_id, organization_id)
        REFERENCES public.roles (id, organization_id)
        ON DELETE CASCADE
);

CREATE INDEX membership_roles_role_id_idx
    ON public.membership_roles (role_id);

CREATE TABLE public.role_permissions (
    organization_id UUID NOT NULL,
    role_id UUID NOT NULL,
    permission_code VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    PRIMARY KEY (role_id, permission_code),

    CONSTRAINT role_permissions_role_fk
        FOREIGN KEY (role_id, organization_id)
        REFERENCES public.roles (id, organization_id)
        ON DELETE CASCADE,

    CONSTRAINT role_permissions_permission_fk
        FOREIGN KEY (permission_code)
        REFERENCES public.permissions (code)
        ON DELETE RESTRICT
);

-- ============================================================================
-- 03. SECURITY TABLES
-- ============================================================================

CREATE TABLE auth_security.public_keys (
    kid VARCHAR(100) PRIMARY KEY,
    public_key BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ,

    CONSTRAINT public_keys_kid_not_empty
        CHECK (length(btrim(kid)) > 0),

    CONSTRAINT public_keys_ed25519_length
        CHECK (octet_length(public_key) = 32)
);

CREATE TABLE auth_security.used_jti (
    jti UUID PRIMARY KEY,
    used_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE auth_security.transaction_context (
    txid XID8 PRIMARY KEY,
    user_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    cleaned_at TIMESTAMPTZ,

    CONSTRAINT transaction_context_expiry_check
        CHECK (expires_at > issued_at),

    CONSTRAINT transaction_context_lifetime_check
        CHECK (expires_at <= issued_at + INTERVAL '60 seconds')
);

CREATE INDEX transaction_context_expiry_idx
    ON auth_security.transaction_context (expires_at);

CREATE INDEX used_jti_used_at_idx
    ON auth_security.used_jti (used_at);

-- ============================================================================
-- 04. CONTEXT ACCESS FUNCTION
-- ============================================================================
-- No GUC is used as an authority or as a context pointer.
-- The identity is retrieved only by the current transaction XID8.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_security.securebiz_get_context(
    p_field TEXT
)
RETURNS UUID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_value UUID;
BEGIN
    IF p_field IS NULL
       OR p_field NOT IN ('user_id', 'organization_id') THEN
        RETURN NULL;
    END IF;

    SELECT
        CASE p_field
            WHEN 'user_id' THEN tc.user_id
            WHEN 'organization_id' THEN tc.organization_id
        END
      INTO v_value
      FROM auth_security.transaction_context AS tc
     WHERE tc.txid = pg_catalog.pg_current_xact_id()
       AND tc.expires_at > pg_catalog.clock_timestamp()
       AND tc.cleaned_at IS NULL;

    RETURN v_value;
END;
$function$;

-- ============================================================================
-- 05. SIGNED CONTEXT INSTALLATION
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_security.securebiz_install_context(
    p_payload TEXT,
    p_signature BYTEA,
    p_key_id VARCHAR(100)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    v_public_key BYTEA;
    v_claims JSONB;
    v_user_id UUID;
    v_org_id UUID;
    v_jti UUID;
    v_iss TEXT;
    v_aud TEXT;
    v_iat BIGINT;
    v_exp BIGINT;
    v_now BIGINT;
BEGIN
    IF p_payload IS NULL
       OR p_signature IS NULL
       OR p_key_id IS NULL
       OR length(btrim(p_key_id)) = 0 THEN
        RAISE EXCEPTION 'Missing cryptographic input';
    END IF;

    IF octet_length(pg_catalog.convert_to(p_payload, 'UTF8')) > 8192 THEN
        RAISE EXCEPTION 'Payload exceeds maximum permitted size';
    END IF;

    IF octet_length(p_signature) <> 64 THEN
        RAISE EXCEPTION 'Invalid Ed25519 signature length';
    END IF;

    -- A transaction may receive only one context, even if it is cleaned.
    IF EXISTS (
        SELECT 1
          FROM auth_security.transaction_context AS tc
         WHERE tc.txid = pg_catalog.pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION
            'A context has already been installed in this transaction';
    END IF;

    SELECT pk.public_key
      INTO v_public_key
      FROM auth_security.public_keys AS pk
     WHERE pk.kid = p_key_id
       AND pk.revoked_at IS NULL;

    IF v_public_key IS NULL THEN
        RAISE EXCEPTION 'Unknown or revoked signing key';
    END IF;

    IF pgsodium.crypto_sign_verify_detached(
        p_signature,
        pg_catalog.convert_to(p_payload, 'UTF8'),
        v_public_key
    ) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Invalid Ed25519 signature';
    END IF;

    -- Parse only after verifying the exact signed UTF-8 payload.
    v_claims := p_payload::JSONB;

    IF pg_catalog.jsonb_typeof(v_claims) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'Payload must be a JSON object';
    END IF;

    IF pg_catalog.jsonb_typeof(v_claims->'iss') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(v_claims->'aud') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(v_claims->'sub') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(v_claims->'org') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(v_claims->'jti') IS DISTINCT FROM 'string'
       OR pg_catalog.jsonb_typeof(v_claims->'iat') IS DISTINCT FROM 'number'
       OR pg_catalog.jsonb_typeof(v_claims->'exp') IS DISTINCT FROM 'number' THEN
        RAISE EXCEPTION 'Missing claim or invalid claim type';
    END IF;

    IF (v_claims->>'iat') !~ '^[0-9]{1,12}$'
       OR (v_claims->>'exp') !~ '^[0-9]{1,12}$' THEN
        RAISE EXCEPTION
            'iat and exp must be positive integer Unix timestamps';
    END IF;

    BEGIN
        v_iss := v_claims->>'iss';
        v_aud := v_claims->>'aud';
        v_user_id := (v_claims->>'sub')::UUID;
        v_org_id := (v_claims->>'org')::UUID;
        v_jti := (v_claims->>'jti')::UUID;
        v_iat := (v_claims->>'iat')::BIGINT;
        v_exp := (v_claims->>'exp')::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION 'Invalid UUID or timestamp claim';
    END;

    IF v_iss <> 'securebiz-api' THEN
        RAISE EXCEPTION 'Invalid issuer';
    END IF;

    IF v_aud <> 'securebiz-postgres' THEN
        RAISE EXCEPTION 'Invalid audience';
    END IF;
 
    IF v_jti = '00000000-0000-0000-0000-000000000000'::UUID THEN
        RAISE EXCEPTION 'Invalid JTI';
    END IF;

    v_now := floor(
        EXTRACT(EPOCH FROM clock_timestamp())
    )::BIGINT;

    IF v_iat > v_now + 5 THEN
        RAISE EXCEPTION 'Token issued too far in the future';
    END IF;

    IF v_exp <= v_iat THEN
        RAISE EXCEPTION 'Token expiration must be after issuance';
    END IF;

    IF (v_exp - v_iat) > 60 THEN
        RAISE EXCEPTION 'Token lifetime exceeds 60 seconds';
    END IF;

    IF pg_catalog.to_timestamp(v_exp) <= pg_catalog.clock_timestamp() THEN
        RAISE EXCEPTION 'Token expired';
    END IF;

    -- Lock the identity and membership rows until transaction completion.
    -- This prevents concurrent suspension/deactivation during this transaction.
    PERFORM 1
      FROM public.users AS u
      JOIN public.memberships AS m
        ON m.user_id = u.id
      JOIN public.organizations AS o
        ON o.id = m.organization_id
     WHERE u.id = v_user_id
       AND m.organization_id = v_org_id
       AND u.status = 'active'
       AND m.status = 'active'
       AND o.status = 'active'
     FOR SHARE OF u, m, o;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Inactive or unauthorized user membership';
    END IF;

    -- Atomic anti-replay insertion.
    INSERT INTO auth_security.used_jti (jti)
    VALUES (v_jti)
    ON CONFLICT (jti) DO NOTHING;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Token replay detected';
    END IF;

    INSERT INTO auth_security.transaction_context (
        txid,
        user_id,
        organization_id,
        issued_at,
        expires_at
    )
    VALUES (
        pg_catalog.pg_current_xact_id(),
        v_user_id,
        v_org_id,
        pg_catalog.to_timestamp(v_iat),
        pg_catalog.to_timestamp(v_exp)
    );

    RETURN TRUE;
END;
$function$;

-- ============================================================================
-- 06. RBAC PERMISSION CHECK
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_security.app_has_permission(
    p_permission_code TEXT
)
RETURNS BOOLEAN
LANGUAGE SQL
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT EXISTS (
        SELECT 1
          FROM public.memberships AS m
          JOIN public.membership_roles AS mr
            ON mr.membership_id = m.id
           AND mr.organization_id = m.organization_id
          JOIN public.roles AS r
            ON r.id = mr.role_id
           AND r.organization_id = mr.organization_id
          JOIN public.role_permissions AS rp
            ON rp.role_id = r.id
           AND rp.organization_id = r.organization_id
          JOIN public.organizations AS o
            ON o.id = m.organization_id
         WHERE m.user_id =
               auth_security.securebiz_get_context('user_id')
           AND m.organization_id =
               auth_security.securebiz_get_context('organization_id')
           AND m.status = 'active'
           AND o.status = 'active'
           AND rp.permission_code = p_permission_code
    );
$function$;

-- ============================================================================
-- 07. AUTHENTICATION FUNCTION
-- ============================================================================
-- securebiz_auth receives no direct SELECT privilege on credentials or users.
-- It can only call this narrowly scoped function.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_private.authenticate(
    p_email VARCHAR
)
RETURNS TABLE (
    user_id UUID,
    password_hash TEXT,
    status VARCHAR
)
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT u.id, c.password_hash, u.status
      FROM public.users AS u
      JOIN auth_private.credentials AS c
        ON c.user_id = u.id
     WHERE pg_catalog.lower(u.email) = pg_catalog.lower(p_email);
$function$;

-- ============================================================================
-- 08. CONTEXT CLEANUP AND CONTROLLED PURGE
-- ============================================================================

-- Mark the current transaction context as cleaned.
-- Keep its row until purge so a second identity cannot be installed
-- in the same transaction after cleanup.
CREATE OR REPLACE FUNCTION auth_security.securebiz_cleanup_context()
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    UPDATE auth_security.transaction_context
       SET cleaned_at = pg_catalog.clock_timestamp()
     WHERE txid = pg_catalog.pg_current_xact_id()
       AND cleaned_at IS NULL;
END;
$function$;

-- Administrative maintenance only.
-- Not granted to securebiz_app or securebiz_auth.
CREATE OR REPLACE FUNCTION auth_security.securebiz_purge_expired_security_data()
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    DELETE FROM auth_security.transaction_context
     WHERE expires_at < pg_catalog.clock_timestamp() - INTERVAL '10 minutes';

    DELETE FROM auth_security.used_jti
     WHERE used_at < pg_catalog.clock_timestamp() - INTERVAL '10 minutes';
END;
$function$;

-- ============================================================================
-- 09. PUBLIC KEY ADMINISTRATION
-- ============================================================================
-- These functions are administrative. They are not granted to app/auth.
-- Vault private keys never enter PostgreSQL.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_security.securebiz_register_public_key(
    p_kid VARCHAR(100),
    p_public_key BYTEA
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
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

CREATE OR REPLACE FUNCTION auth_security.securebiz_revoke_public_key(
    p_kid VARCHAR(100)
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    UPDATE auth_security.public_keys
       SET revoked_at = pg_catalog.clock_timestamp()
     WHERE kid = p_kid
       AND revoked_at IS NULL;

    RETURN FOUND;
END;
$function$;

-- ============================================================================
-- 10. SYSTEM ROLE PROTECTION
-- ============================================================================
-- The application cannot create, promote, modify or delete system roles.
-- Trusted migration/admin operations remain possible.
-- ============================================================================

CREATE OR REPLACE FUNCTION auth_security.prevent_system_role_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF current_user = 'securebiz_app' THEN
        IF TG_OP = 'INSERT' THEN
            IF NEW.is_system THEN
                RAISE EXCEPTION 'Application cannot create system roles';
            END IF;
            RETURN NEW;

        ELSIF TG_OP = 'UPDATE' THEN
            IF OLD.is_system OR NEW.is_system THEN
                RAISE EXCEPTION
                    'Application cannot modify or promote system roles';
            END IF;
            RETURN NEW;

        ELSIF TG_OP = 'DELETE' THEN
            IF OLD.is_system THEN
                RAISE EXCEPTION 'Application cannot delete system roles';
            END IF;
            RETURN OLD;
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    RETURN NEW;
END;
$function$;

CREATE TRIGGER roles_system_protection
BEFORE INSERT OR UPDATE OR DELETE ON public.roles
FOR EACH ROW
EXECUTE FUNCTION auth_security.prevent_system_role_modification();

-- ============================================================================
-- 11. TRANSFER OWNERSHIP OF SECURITY FUNCTIONS
-- ============================================================================

ALTER FUNCTION auth_security.securebiz_get_context(TEXT)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.securebiz_install_context(TEXT, BYTEA, VARCHAR)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.app_has_permission(TEXT)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_private.authenticate(VARCHAR)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.securebiz_cleanup_context()
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.securebiz_purge_expired_security_data()
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.securebiz_register_public_key(VARCHAR, BYTEA)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.securebiz_revoke_public_key(VARCHAR)
    OWNER TO securebiz_owner;

ALTER FUNCTION auth_security.prevent_system_role_modification()
    OWNER TO securebiz_owner;

-- The owner no longer needs CREATE on either security schema.
REVOKE CREATE ON SCHEMA auth_security, auth_private
    FROM securebiz_owner;

-- ============================================================================
-- 12. ENABLE AND FORCE ROW LEVEL SECURITY
-- ============================================================================

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations FORCE ROW LEVEL SECURITY;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;

ALTER TABLE public.memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.memberships FORCE ROW LEVEL SECURITY;

ALTER TABLE public.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.roles FORCE ROW LEVEL SECURITY;

ALTER TABLE public.membership_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.membership_roles FORCE ROW LEVEL SECURITY;

ALTER TABLE public.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.role_permissions FORCE ROW LEVEL SECURITY;

-- Security-definer functions owned by securebiz_owner need controlled access.
CREATE POLICY owner_organizations_policy
ON public.organizations FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY owner_users_policy
ON public.users FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY owner_memberships_policy
ON public.memberships FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY owner_roles_policy
ON public.roles FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY owner_membership_roles_policy
ON public.membership_roles FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY owner_role_permissions_policy
ON public.role_permissions FOR ALL TO securebiz_owner
USING (TRUE) WITH CHECK (TRUE);

-- ============================================================================
-- 13. APPLICATION RLS POLICIES
-- ============================================================================

CREATE POLICY organizations_select_policy
ON public.organizations
FOR SELECT TO securebiz_app
USING (
    id = auth_security.securebiz_get_context('organization_id')
);

CREATE POLICY users_select_policy
ON public.users
FOR SELECT TO securebiz_app
USING (
    auth_security.app_has_permission('users:read')
    AND EXISTS (
        SELECT 1
          FROM public.memberships AS m
         WHERE m.user_id = users.id
           AND m.organization_id =
               auth_security.securebiz_get_context('organization_id')
           AND m.status = 'active'
    )
);

CREATE POLICY memberships_select_policy
ON public.memberships
FOR SELECT TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('users:read')
);

CREATE POLICY memberships_insert_policy
ON public.memberships
FOR INSERT TO securebiz_app
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('users:invite')
);

CREATE POLICY memberships_update_policy
ON public.memberships
FOR UPDATE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('users:update')
)
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('users:update')
);

CREATE POLICY memberships_delete_policy
ON public.memberships
FOR DELETE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('users:deactivate')
);

CREATE POLICY roles_select_policy
ON public.roles
FOR SELECT TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:read')
);

CREATE POLICY roles_insert_policy
ON public.roles
FOR INSERT TO securebiz_app
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND NOT is_system
    AND auth_security.app_has_permission('roles:create')
);

CREATE POLICY roles_update_policy
ON public.roles
FOR UPDATE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND NOT is_system
    AND auth_security.app_has_permission('roles:update')
)
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND NOT is_system
    AND auth_security.app_has_permission('roles:update')
);

CREATE POLICY roles_delete_policy
ON public.roles
FOR DELETE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND NOT is_system
    AND auth_security.app_has_permission('roles:delete')
);

CREATE POLICY membership_roles_select_policy
ON public.membership_roles
FOR SELECT TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:read')
);

CREATE POLICY membership_roles_insert_policy
ON public.membership_roles
FOR INSERT TO securebiz_app
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:update')
);

CREATE POLICY membership_roles_delete_policy
ON public.membership_roles
FOR DELETE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:update')
);

CREATE POLICY role_permissions_select_policy
ON public.role_permissions
FOR SELECT TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:read')
);

CREATE POLICY role_permissions_insert_policy
ON public.role_permissions
FOR INSERT TO securebiz_app
WITH CHECK (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:update')
    AND EXISTS (
        SELECT 1
          FROM public.roles AS r
         WHERE r.id = role_permissions.role_id
           AND r.organization_id = role_permissions.organization_id
           AND NOT r.is_system
    )
);

CREATE POLICY role_permissions_delete_policy
ON public.role_permissions
FOR DELETE TO securebiz_app
USING (
    organization_id =
        auth_security.securebiz_get_context('organization_id')
    AND auth_security.app_has_permission('roles:update')
    AND EXISTS (
        SELECT 1
          FROM public.roles AS r
         WHERE r.id = role_permissions.role_id
           AND r.organization_id = role_permissions.organization_id
           AND NOT r.is_system
    )
);

-- ============================================================================
-- 14. PERMISSION CATALOG
-- ============================================================================

INSERT INTO public.permissions (code, description)
VALUES
    ('users:read', 'View organization users'),
    ('users:invite', 'Invite users to an organization'),
    ('users:update', 'Update organization memberships'),
    ('users:deactivate', 'Deactivate organization memberships'),
    ('roles:read', 'View organization roles'),
    ('roles:create', 'Create organization roles'),
    ('roles:update', 'Assign roles and manage custom role permissions'),
    ('roles:delete', 'Delete custom organization roles'),
    ('permissions:read', 'View available permissions'),
    ('reports:read', 'View security reports'),
    ('reports:create', 'Create security reports')
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- 15. REVOKE PUBLIC ACCESS TO OUR OBJECTS
-- ============================================================================

REVOKE ALL ON TABLE
    public.organizations,
    public.users,
    public.memberships,
    public.roles,
    public.permissions,
    public.membership_roles,
    public.role_permissions,
    auth_private.credentials,
    auth_security.public_keys,
    auth_security.used_jti,
    auth_security.transaction_context
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_get_context(TEXT)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_install_context(TEXT, BYTEA, VARCHAR)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.app_has_permission(TEXT)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_private.authenticate(VARCHAR)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_cleanup_context()
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_purge_expired_security_data()
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_register_public_key(VARCHAR, BYTEA)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.securebiz_revoke_public_key(VARCHAR)
FROM PUBLIC;

REVOKE ALL ON FUNCTION
    auth_security.prevent_system_role_modification()
FROM PUBLIC;

-- ============================================================================
-- 16. MINIMUM PRIVILEGES
-- ============================================================================

-- securebiz_owner: read business data for security-definer checks.
GRANT SELECT ON
    public.organizations,
    public.users,
    public.memberships,
    public.roles,
    public.membership_roles,
    public.role_permissions
TO securebiz_owner;

GRANT SELECT ON auth_private.credentials
    TO securebiz_owner;

GRANT SELECT, INSERT, UPDATE ON auth_security.public_keys
    TO securebiz_owner;

GRANT SELECT, INSERT, DELETE ON auth_security.used_jti
    TO securebiz_owner;

GRANT SELECT, INSERT, UPDATE, DELETE
    ON auth_security.transaction_context
    TO securebiz_owner;

GRANT EXECUTE ON FUNCTION
    pgsodium.crypto_sign_verify_detached(BYTEA, BYTEA, BYTEA)
TO securebiz_owner;

-- Application role: business access remains constrained by RLS.
GRANT SELECT ON
    public.organizations,
    public.users,
    public.permissions
TO securebiz_app;

GRANT SELECT, INSERT, UPDATE, DELETE
    ON public.memberships
TO securebiz_app;

GRANT SELECT, INSERT, UPDATE, DELETE
    ON public.roles
TO securebiz_app;

GRANT SELECT, INSERT, DELETE
    ON public.membership_roles
TO securebiz_app;

GRANT SELECT, INSERT, DELETE
    ON public.role_permissions
TO securebiz_app;

GRANT EXECUTE ON FUNCTION
    auth_security.securebiz_install_context(TEXT, BYTEA, VARCHAR)
TO securebiz_app;

GRANT EXECUTE ON FUNCTION
    auth_security.securebiz_get_context(TEXT)
TO securebiz_app;

GRANT EXECUTE ON FUNCTION
    auth_security.app_has_permission(TEXT)
TO securebiz_app;

GRANT EXECUTE ON FUNCTION
    auth_security.securebiz_cleanup_context()
TO securebiz_app;

-- Authentication role: only the narrow authentication function.
GRANT EXECUTE ON FUNCTION
    auth_private.authenticate(VARCHAR)
TO securebiz_auth;

-- No direct application or authentication access to:
--   auth_private.credentials
--   auth_security.public_keys
--   auth_security.used_jti
--   auth_security.transaction_context

-- ============================================================================
-- 17. COMPLETION
-- ============================================================================

DO $completion$
BEGIN
    RAISE NOTICE 'SecureBiz IAM V8 objects created.';
    RAISE NOTICE 'This migration has not performed functional security tests.';
    RAISE NOTICE 'Context installation and business queries must share one transaction.';
    RAISE NOTICE 'Public key registration is an administrative operation.';
END;
$completion$;

COMMIT;

-- ============================================================================
-- SecureBiz Lab -- Migration 002
-- Authentication sessions and refresh token storage
-- PostgreSQL 16
-- ============================================================================

BEGIN;

-- 1. Dedicated schema
CREATE SCHEMA auth_session;
REVOKE ALL ON SCHEMA auth_session FROM PUBLIC;
GRANT USAGE ON SCHEMA auth_session TO securebiz_auth;
GRANT USAGE ON SCHEMA auth_session TO securebiz_owner;
REVOKE ALL ON SCHEMA auth_session FROM securebiz_app;

-- 2. Refresh token storage
CREATE TABLE auth_session.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    family_id       UUID NOT NULL,
    token_hash      BYTEA NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID REFERENCES auth_session.refresh_tokens(id),
    user_agent      TEXT,
    ip_address      INET,
    CONSTRAINT refresh_tokens_hash_length_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_expiration_check CHECK (expires_at > issued_at),
    CONSTRAINT refresh_tokens_unique_hash UNIQUE (token_hash)
);

-- 3. Indexes
CREATE INDEX idx_refresh_tokens_user_id ON auth_session.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_family_id ON auth_session.refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires_at ON auth_session.refresh_tokens(expires_at);

-- 4. Ownership
ALTER SCHEMA auth_session OWNER TO securebiz_user;
ALTER TABLE auth_session.refresh_tokens OWNER TO securebiz_user;

-- 5. Permissions on refresh_tokens
REVOKE ALL ON TABLE auth_session.refresh_tokens FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON TABLE auth_session.refresh_tokens TO securebiz_auth;
REVOKE ALL ON TABLE auth_session.refresh_tokens FROM securebiz_app;
GRANT SELECT ON TABLE auth_session.refresh_tokens TO securebiz_owner;

-- 6. Function: get_user_status
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

ALTER FUNCTION auth_session.get_user_status(UUID) OWNER TO securebiz_owner;
REVOKE ALL ON FUNCTION auth_session.get_user_status(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_session.get_user_status(UUID) TO securebiz_auth;

-- 7. Documentation
COMMENT ON TABLE auth_session.refresh_tokens IS 'Stores SHA-256 hashes of opaque refresh tokens. Tokens are rotated on use and grouped into revocable families.';
COMMENT ON COLUMN auth_session.refresh_tokens.token_hash IS 'SHA-256 hash of the opaque refresh token. Never store raw tokens.';
COMMENT ON COLUMN auth_session.refresh_tokens.family_id IS 'Identifies the refresh token family used for rotation and reuse detection.';
COMMENT ON FUNCTION auth_session.get_user_status(UUID) IS 'Returns the status of a user without exposing public.users. SECURITY DEFINER, executable only by securebiz_auth.';

COMMIT;

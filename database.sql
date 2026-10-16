-- ============================================================
--  COMPLETE DATABASE SCHEMA — AIA Gap Analysis Platform
--  Run this in Supabase SQL Editor
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
--  ORGANIZATIONS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);

-- ============================================================
--  USERS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    org_id UUID REFERENCES organizations(id),
    role TEXT NOT NULL DEFAULT 'respondent',
    is_pro_owner BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);

-- ============================================================
--  SESSIONS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE DEFAULT encode(gen_random_bytes(32), 'hex'),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '7 days',
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- ============================================================
--  LOGIN_AUDIT TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS login_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    event TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_audit_user_id ON login_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_login_audit_email ON login_audit(email);
CREATE INDEX IF NOT EXISTS idx_login_audit_created_at ON login_audit(created_at);

-- ============================================================
--  PROCESSES TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS processes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    department TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_processes_org_id ON processes(org_id);

-- ============================================================
--  GAPS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    process_id UUID NOT NULL REFERENCES processes(id) ON DELETE CASCADE,
    respondent_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gaps_process_id ON gaps(process_id);
CREATE INDEX IF NOT EXISTS idx_gaps_respondent_id ON gaps(respondent_id);

-- ============================================================
--  GAP_RESPONSES TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS gap_responses (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dept TEXT NOT NULL,
    proc_id TEXT NOT NULL,
    gaps JSONB DEFAULT '[]'::JSONB,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gap_responses_user_id ON gap_responses(user_id);
CREATE INDEX IF NOT EXISTS idx_gap_responses_proc_id ON gap_responses(proc_id);

-- ============================================================
--  RPC FUNCTIONS
-- ============================================================

-- Register a new user
DROP FUNCTION IF EXISTS register_user(TEXT, TEXT, TEXT, TEXT, TEXT, BOOLEAN);
CREATE OR REPLACE FUNCTION register_user(
    p_email         TEXT,
    p_password      TEXT,
    p_full_name     TEXT,
    p_org_slug      TEXT    DEFAULT NULL,
    p_role          TEXT    DEFAULT 'respondent',
    p_is_pro_owner  BOOLEAN DEFAULT FALSE
)
RETURNS TABLE(user_id UUID, token TEXT, full_name TEXT, role TEXT, org_slug TEXT, is_pro_owner BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_org_id    UUID;
    v_user_id   UUID;
    v_token     TEXT;
    v_email     TEXT := lower(trim(p_email));
BEGIN
    IF EXISTS (SELECT 1 FROM users WHERE email = v_email) THEN
        RAISE EXCEPTION 'EMAIL_TAKEN';
    END IF;

    IF p_org_slug IS NOT NULL THEN
        SELECT id INTO v_org_id
        FROM organizations
        WHERE slug = lower(trim(p_org_slug)) AND is_active = TRUE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'ORG_NOT_FOUND';
        END IF;
    END IF;

    INSERT INTO users (email, password_hash, full_name, org_id, role, is_pro_owner)
    VALUES (
        v_email,
        crypt(p_password, gen_salt('bf', 10)),
        p_full_name,
        v_org_id,
        p_role,
        p_is_pro_owner
    )
    RETURNING id INTO v_user_id;

    INSERT INTO sessions (user_id)
    VALUES (v_user_id)
    RETURNING sessions.token INTO v_token;

    INSERT INTO login_audit (user_id, email, event)
    VALUES (v_user_id, v_email, 'signup');

    RETURN QUERY
    SELECT v_user_id, v_token, p_full_name, p_role, p_org_slug, p_is_pro_owner;
END;
$$;

-- Authenticate a user
DROP FUNCTION IF EXISTS authenticate_user(TEXT, TEXT, INET, TEXT);
CREATE OR REPLACE FUNCTION authenticate_user(
    p_email     TEXT,
    p_password  TEXT,
    p_ip        INET    DEFAULT NULL,
    p_agent     TEXT    DEFAULT NULL
)
RETURNS TABLE(user_id UUID, token TEXT, full_name TEXT, role TEXT, org_slug TEXT, is_pro_owner BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_user      users%ROWTYPE;
    v_token     TEXT;
    v_org_slug  TEXT;
    v_email     TEXT := lower(trim(p_email));
BEGIN
    SELECT * INTO v_user
    FROM users
    WHERE email = v_email AND is_active = TRUE;

    IF NOT FOUND OR v_user.password_hash <> crypt(p_password, v_user.password_hash) THEN
        INSERT INTO login_audit (user_id, email, event, ip_address, user_agent)
        VALUES (NULL, v_email, 'login_failed', p_ip, p_agent);
        RAISE EXCEPTION 'INVALID_CREDENTIALS';
    END IF;

    INSERT INTO sessions (user_id, ip_address, user_agent)
    VALUES (v_user.id, p_ip, p_agent)
    RETURNING sessions.token INTO v_token;

    SELECT slug INTO v_org_slug FROM organizations WHERE id = v_user.org_id;

    INSERT INTO login_audit (user_id, email, event, ip_address, user_agent)
    VALUES (v_user.id, v_email, 'login_success', p_ip, p_agent);

    RETURN QUERY
    SELECT v_user.id, v_token, v_user.full_name, v_user.role, v_org_slug, v_user.is_pro_owner;
END;
$$;

-- Validate a session token
DROP FUNCTION IF EXISTS validate_session(TEXT);
CREATE OR REPLACE FUNCTION validate_session(p_token TEXT)
RETURNS TABLE(user_id UUID, full_name TEXT, role TEXT, org_slug TEXT, is_pro_owner BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.full_name, u.role, o.slug, u.is_pro_owner
    FROM sessions s
    JOIN  users         u ON u.id = s.user_id
    LEFT  JOIN organizations o ON o.id = u.org_id
    WHERE s.token = p_token
      AND s.expires_at > NOW()
      AND u.is_active = TRUE;
END;
$$;

-- Load gap responses for the current user (by token)
DROP FUNCTION IF EXISTS load_gap_responses(TEXT);
CREATE OR REPLACE FUNCTION load_gap_responses(p_token TEXT)
RETURNS TABLE(proc_id TEXT, gaps JSONB, updated_at TIMESTAMP WITH TIME ZONE)
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_user_id UUID;
BEGIN
    SELECT u.id INTO v_user_id
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = p_token
      AND s.expires_at > NOW()
      AND u.is_active = TRUE
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT gr.proc_id, gr.gaps, gr.updated_at
    FROM gap_responses gr
    WHERE gr.user_id = v_user_id
    ORDER BY gr.updated_at DESC;
END;
$$;

-- Load all gap responses for an organization (for summary view)
DROP FUNCTION IF EXISTS load_all_gap_responses();
CREATE OR REPLACE FUNCTION load_all_gap_responses()
RETURNS TABLE(proc_id TEXT, dept TEXT, gaps JSONB, user_id UUID, updated_at TIMESTAMP WITH TIME ZONE)
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN QUERY
    SELECT gr.proc_id, gr.dept, gr.gaps, gr.user_id, gr.updated_at
    FROM gap_responses gr
    ORDER BY gr.proc_id, gr.updated_at DESC;
END;
$$;

-- ============================================================
--  PERMISSIONS / GRANTS
-- ============================================================
GRANT EXECUTE ON FUNCTION register_user(TEXT, TEXT, TEXT, TEXT, TEXT, BOOLEAN)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION authenticate_user(TEXT, TEXT, INET, TEXT)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION validate_session(TEXT)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION load_gap_responses(TEXT)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION load_all_gap_responses()
    TO anon, authenticated;

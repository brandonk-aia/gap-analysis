-- ============================================================
--  MIGRATION: Add is_pro_owner column + update affected functions
--  Run this against the existing database.
-- ============================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS
    is_pro_owner BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill any existing users who should be process owners.
-- Replace the email value(s) before running.
UPDATE users SET is_pro_owner = TRUE
WHERE email IN ('replace-with-user@email.com');

-- ============================================================
--  UPDATED FUNCTIONS
-- ============================================================

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
        VALUES (v_user.id, v_email, 'login_failed', p_ip, p_agent);
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

-- ============================================================
--  GRANTS
-- ============================================================

GRANT EXECUTE ON FUNCTION register_user(TEXT, TEXT, TEXT, TEXT, TEXT, BOOLEAN)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION authenticate_user(TEXT, TEXT, INET, TEXT)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION validate_session(TEXT)
    TO anon, authenticated;

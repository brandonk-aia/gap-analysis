-- ============================================================
--  FIX: users.is_active missing
--  The live users table was created before database.sql, with an
--  "active" column instead of "is_active". CREATE TABLE IF NOT EXISTS
--  skipped it, so authenticate_user / validate_session fail with
--  'column "is_active" does not exist'.
--  Run this once in the Supabase SQL Editor.
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'is_active'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'active'
        ) THEN
            -- Mirror the existing column so older functions using "active" keep working
            ALTER TABLE users
                ADD COLUMN is_active BOOLEAN GENERATED ALWAYS AS (COALESCE(active, TRUE)) STORED;
        ELSE
            ALTER TABLE users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
        END IF;
    END IF;
END;
$$;

-- Columns the auth functions rely on (no-ops if they already exist)
ALTER TABLE users    ADD COLUMN IF NOT EXISTS role          TEXT    NOT NULL DEFAULT 'respondent';
ALTER TABLE users    ADD COLUMN IF NOT EXISTS is_pro_owner  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address    INET;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent    TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '7 days';

CREATE TABLE IF NOT EXISTS login_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email TEXT NOT NULL,
    event TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Make PostgREST pick up the schema change immediately
NOTIFY pgrst, 'reload schema';

-- Sanity check: should list is_active
SELECT column_name, data_type, is_generated
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users'
ORDER BY ordinal_position;

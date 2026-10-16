-- ============================================================
--  ADD GAP RESPONSE FUNCTIONS
--  Run this to add missing RPC functions for loading gap responses
-- ============================================================

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

-- Grant permissions
GRANT EXECUTE ON FUNCTION load_gap_responses(TEXT)
    TO anon, authenticated;

GRANT EXECUTE ON FUNCTION load_all_gap_responses()
    TO anon, authenticated;

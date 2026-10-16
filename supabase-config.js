// ============================================================
//  Supabase client configuration
//  Fill in your project URL and anon key.
//  Find them at: Supabase Dashboard → Settings → API
//
//  This file is loaded by auth.html and gap_analysis.html via
//  a <script> tag before any other app scripts.
// ============================================================

const SUPABASE_URL      = 'https://zmcizacshrlxlhkbynep.supabase.co';
const SUPABASE_ANON_KEY = 'sb_publishable_2BODQAV7xC3JlFaUZvB3Rg_S9YFgY2P';

// Initialise the global Supabase client.
// Requires the supabase-js CDN script to be loaded first.
const _supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
        // Use localStorage so the session persists across page loads
        storage:          window.localStorage,
        autoRefreshToken: true,
        persistSession:   true,
        detectSessionInUrl: false
    }
});

// Expose as a named export-like global so all pages can use it
window._db = _supabaseClient;

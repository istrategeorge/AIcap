-- Migration: bootstrap the api_keys table that backs Pro CLI authentication.
--
-- Originally lived in frontend/src/init.sql and was applied by hand through
-- the Supabase SQL console. Re-running it here is safe: IF NOT EXISTS gates
-- every object so production (where the table is already present) is a no-op,
-- while a fresh local/integration DB gets the full schema.

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- In Supabase this references auth.users(id); on a bare Postgres used for
    -- integration tests there is no auth schema, so we keep the column as a
    -- plain UUID and rely on the application layer to enforce the linkage.
    user_id UUID NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

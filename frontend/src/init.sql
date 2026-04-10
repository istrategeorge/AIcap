-- 1. Projects Table
-- API Keys Table
-- Stores the generated Pro SaaS tokens for authenticated users
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- In Supabase, this links securely to their built-in Auth system
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
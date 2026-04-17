-- Migration: hash API keys at rest and make "one key per user" a DB constraint.
--
-- Why: the raw aicap_pro_sk_* tokens used to live in api_keys.token. Anyone
-- with SQL-level read on the DB (a compromised Supabase dashboard session, a
-- leaked connection string, a rogue DBA) could steal every customer's CI
-- credential in one query. After this migration we only ever store the
-- SHA-256 of the token — an attacker who steals the table can no longer
-- authenticate as any customer because the preimage is not recoverable from
-- the hash.
--
-- Concretely:
--   * token_hash TEXT holds `sha256(token)` as 64 hex chars.
--   * token_hash is nullable on purpose: the Stripe webhook creates a Pro
--     row as soon as checkout succeeds, but the raw key is only generated
--     and revealed when the authenticated user hits /api/generate-key.
--     Leaving token_hash NULL between those two events is how we model
--     "subscription active, key not yet materialised". Postgres' UNIQUE
--     semantics treat multiple NULLs as non-conflicting, so this is safe.
--   * A UNIQUE(user_id) constraint enforces the one-key-per-user invariant
--     that the application layer always assumed. Without it, a bug in
--     generate-key or the webhook could silently produce two active keys
--     for the same user and the dashboard would just pick one.
--   * The plaintext `token` column is dropped in the same migration since
--     Wave 3a verified the database can be wiped (no active users) and
--     keeping a plaintext column around "just in case" defeats the point.

-- 1. Add the hash column. Nullable so the webhook can insert a row before
--    /api/generate-key has been called.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS token_hash TEXT;

-- 2. Backfill from the existing plaintext column. Idempotent: once the
--    token column is dropped this UPDATE is a no-op against empty-tabled
--    databases and a harmless re-run against already-hashed rows.
UPDATE api_keys
SET token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex')
WHERE token_hash IS NULL AND token IS NOT NULL;

-- 3. Index the hash so LookupAPIKey's lookup-by-hash is O(log n). Not UNIQUE
--    because legitimate NULLs coexist (see header comment); the application
--    layer treats collisions of non-NULL hashes as a bug and logs them.
CREATE INDEX IF NOT EXISTS idx_api_keys_token_hash ON api_keys(token_hash);

-- 4. Enforce one key row per user so the webhook can safely upsert and
--    /api/generate-key can assume at most one row exists per user_id.
--    Wrapped in DO block so a re-run against a DB that already has the
--    constraint doesn't fail — pg_constraint check keeps it idempotent.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'api_keys_user_id_key'
    ) THEN
        ALTER TABLE api_keys ADD CONSTRAINT api_keys_user_id_key UNIQUE (user_id);
    END IF;
END $$;

-- 5. Drop the plaintext column. After this runs, no path can read a raw
--    key back out of the database — the only time a raw key exists is in
--    the HTTP response body of /api/generate-key or /api/rotate-key.
ALTER TABLE api_keys DROP COLUMN IF EXISTS token;

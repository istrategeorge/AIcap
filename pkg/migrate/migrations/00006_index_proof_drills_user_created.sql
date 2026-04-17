-- Migration: composite index on (user_id, created_at) so the rolling-window
-- rate-limit check introduced with migration 00006 stays O(log n) per user
-- instead of scanning every row to find scans from the last 30 days.
--
-- The check query is:
--
--   SELECT COUNT(*) FROM proof_drills
--   WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days';
--
-- Without this index that query degrades to a seq scan once the ledger has
-- more than a few thousand rows, which would make /api/save-proof latency
-- grow linearly with the size of the ledger.

CREATE INDEX IF NOT EXISTS idx_proof_drills_user_created
    ON proof_drills(user_id, created_at);

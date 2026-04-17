-- Migration: attribute each proof drill to the authenticated user that
-- produced it, so /api/history and /api/proof can return tenant-scoped
-- results instead of leaking every customer's ledger to every caller.

ALTER TABLE proof_drills ADD COLUMN IF NOT EXISTS user_id UUID;
CREATE INDEX IF NOT EXISTS idx_proof_drills_user ON proof_drills(user_id);

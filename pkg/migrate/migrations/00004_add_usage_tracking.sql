-- Migration: record each API key's subscription tier so rate limits can be
-- enforced per tier.
--
-- NOTE: `scans_this_month` is retained for backwards compatibility with old
-- code paths but is no longer used for rate-limit decisions — see migration
-- 00006, which switches the check to a rolling-window COUNT over proof_drills.
-- The column is kept rather than dropped because removing it would break
-- older deployed binaries during a rolling update window.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(50) DEFAULT 'free';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scans_this_month INT DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_api_keys_tier ON api_keys(subscription_tier);

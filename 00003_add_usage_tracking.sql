-- Migration: Add usage tracking to API keys for monetization rate limiting

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(50) DEFAULT 'free';
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scans_this_month INT DEFAULT 0;

-- Optionally, store the customer ID centrally
CREATE INDEX IF NOT EXISTS idx_api_keys_tier ON api_keys(subscription_tier);

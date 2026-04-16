-- Migration: Add stripe_customer_id to api_keys table for subscription lifecycle management
-- This enables revoking API keys when subscriptions are cancelled

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_api_keys_stripe_customer ON api_keys(stripe_customer_id);

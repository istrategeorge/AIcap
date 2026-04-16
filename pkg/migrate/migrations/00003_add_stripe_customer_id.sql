-- Migration: correlate each api_keys row with its Stripe customer so webhook
-- events (subscription cancelled, invoice failed) can revoke the right key.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_api_keys_stripe_customer ON api_keys(stripe_customer_id);

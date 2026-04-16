-- Migration: persist every Stripe event we have already processed so retries
-- do not double-apply side effects. Stripe guarantees at-least-once delivery
-- — a network blip on our 200 response triggers a retry five minutes later,
-- and without this table the retry would INSERT a second api_keys row (and
-- collide on the UNIQUE(token) constraint) or re-run the tier upgrade.
--
-- The received_at TIMESTAMPTZ column is kept mostly for diagnostics — if we
-- ever see duplicate-event storms we want to know when the original landed.
-- Rows are cheap; a monthly cleanup of anything older than 30 days is a
-- Wave 4 item if volume ever becomes a concern.

CREATE TABLE IF NOT EXISTS stripe_events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

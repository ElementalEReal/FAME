-- Neon FAME Stripe TEST database only, after Stripe 001_intake and 002_marketplace.
-- Enqueues financial facts in the *same* DB transaction as webhook order updates.
-- Does not touch fame_finance; test-only events are never live money.
BEGIN;
CREATE TABLE IF NOT EXISTS fame_stripe.financial_outbox_test (
  provider_event_id TEXT PRIMARY KEY REFERENCES fame_stripe.intake_events(stripe_event_id) ON DELETE RESTRICT,
  order_id UUID NOT NULL REFERENCES fame_stripe.marketplace_orders(order_id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (event_type IN ('MARKETPLACE_PAID','MARKETPLACE_REFUND_UPDATED')),
  payload JSONB NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivery_attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ,
  ledger_journal_id UUID,
  last_error_code TEXT
);
CREATE INDEX IF NOT EXISTS stripe_financial_outbox_pending_idx
  ON fame_stripe.financial_outbox_test(next_attempt_at,created_at)
  WHERE delivered_at IS NULL;
COMMIT;

-- FAME TEST canonical ledger: bridge-order binding and verified-event inbox.
-- Run ONLY on FAME TEST ledger database after backup, after 001_init.sql.
-- No existing fame_finance journals/lines/triggers are modified.
BEGIN;
CREATE TABLE IF NOT EXISTS fame_finance.provider_order_bindings_test (
  order_id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  listing_id TEXT NOT NULL,
  buyer_key TEXT NOT NULL,
  seller_key TEXT NOT NULL,
  amount_minor BIGINT NOT NULL CHECK (amount_minor BETWEEN 1 AND 10000000),
  fee_minor BIGINT NOT NULL CHECK (fee_minor >= 0 AND fee_minor < amount_minor),
  currency_code TEXT NOT NULL CHECK (currency_code = 'USD'),
  stripe_session_id TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS provider_bindings_project_idx
  ON fame_finance.provider_order_bindings_test (tenant_id,project_id);
DROP TRIGGER IF EXISTS provider_bindings_immutable ON fame_finance.provider_order_bindings_test;
CREATE TRIGGER provider_bindings_immutable
  BEFORE UPDATE OR DELETE ON fame_finance.provider_order_bindings_test
  FOR EACH ROW EXECUTE FUNCTION fame_finance.prevent_change();

CREATE TABLE IF NOT EXISTS fame_finance.provider_order_state_test (
  order_id UUID PRIMARY KEY REFERENCES fame_finance.provider_order_bindings_test(order_id) ON DELETE RESTRICT,
  paid_journal_id UUID REFERENCES fame_finance.journals(journal_id) ON DELETE RESTRICT,
  refunded_minor BIGINT NOT NULL DEFAULT 0 CHECK (refunded_minor >= 0),
  refunded_fee_minor BIGINT NOT NULL DEFAULT 0 CHECK (refunded_fee_minor >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fame_finance.provider_event_inbox_test (
  provider_event_id TEXT PRIMARY KEY CHECK (provider_event_id LIKE 'evt_%'),
  order_id UUID NOT NULL REFERENCES fame_finance.provider_order_bindings_test(order_id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (event_type IN ('MARKETPLACE_PAID','MARKETPLACE_REFUND_UPDATED')),
  payload_hash CHAR(64) NOT NULL,
  journal_id UUID REFERENCES fame_finance.journals(journal_id) ON DELETE RESTRICT,
  result_code TEXT NOT NULL CHECK (result_code IN ('POSTED_TEST','BUSINESS_EVENT_ALREADY_APPLIED')),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS provider_inbox_order_idx
  ON fame_finance.provider_event_inbox_test (order_id,received_at);
DROP TRIGGER IF EXISTS provider_inbox_immutable ON fame_finance.provider_event_inbox_test;
CREATE TRIGGER provider_inbox_immutable
  BEFORE UPDATE OR DELETE ON fame_finance.provider_event_inbox_test
  FOR EACH ROW EXECUTE FUNCTION fame_finance.prevent_change();
COMMIT;

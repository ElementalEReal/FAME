-- FAME LIVE settlement acceptance migration. Apply to isolated Neon acceptance branch first.
-- Creates operational clearing journals, NOT finalized bank settlement or payout accounting.
-- Never install fame_finance 001_init.sql in LIVE: it permits only POSTED_TEST.
BEGIN;

ALTER TABLE fame_live.purchase_intents
  ADD COLUMN IF NOT EXISTS refunded_minor INTEGER NOT NULL DEFAULT 0;

ALTER TABLE fame_live.purchase_intents
  ADD CONSTRAINT live_refund_cumulative_check
  CHECK (refunded_minor >= 0 AND refunded_minor <= amount_minor);

CREATE TABLE IF NOT EXISTS fame_live.payment_journals (
  journal_id UUID PRIMARY KEY,
  order_id UUID NOT NULL REFERENCES fame_live.purchase_intents(order_id) ON DELETE RESTRICT,
  provider_event_id TEXT NOT NULL UNIQUE REFERENCES fame_live.provider_events(provider_event_id)
     DEFERRABLE INITIALLY DEFERRED,
  journal_kind TEXT NOT NULL CHECK (journal_kind IN ('PAYMENT_CLEARING','REFUND_CLEARING')),
  currency TEXT NOT NULL CHECK (currency = 'usd'),
  creation_txid BIGINT NOT NULL DEFAULT txid_current(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fame_live.payment_journal_lines (
  journal_id UUID NOT NULL REFERENCES fame_live.payment_journals(journal_id) ON DELETE RESTRICT,
  line_number INTEGER NOT NULL CHECK (line_number BETWEEN 1 AND 20),
  account_code TEXT NOT NULL CHECK (account_code ~ '^[A-Z][A-Z0-9_]{2,39}$'),
  debit_minor BIGINT NOT NULL DEFAULT 0 CHECK (debit_minor >= 0),
  credit_minor BIGINT NOT NULL DEFAULT 0 CHECK (credit_minor >= 0),
  PRIMARY KEY (journal_id, line_number),
  CHECK ((debit_minor > 0 AND credit_minor = 0) OR
         (credit_minor > 0 AND debit_minor = 0))
);

CREATE OR REPLACE FUNCTION fame_live.payment_ledger_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'FAME_LIVE_PAYMENT_JOURNAL_IMMUTABLE' USING ERRCODE='23514';
END $$;

DROP TRIGGER IF EXISTS payment_journals_immutable ON fame_live.payment_journals;
CREATE TRIGGER payment_journals_immutable BEFORE UPDATE OR DELETE ON fame_live.payment_journals
  FOR EACH ROW EXECUTE FUNCTION fame_live.payment_ledger_immutable();
DROP TRIGGER IF EXISTS payment_journal_lines_immutable ON fame_live.payment_journal_lines;
CREATE TRIGGER payment_journal_lines_immutable BEFORE UPDATE OR DELETE ON fame_live.payment_journal_lines
  FOR EACH ROW EXECUTE FUNCTION fame_live.payment_ledger_immutable();

CREATE OR REPLACE FUNCTION fame_live.payment_lines_same_tx()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE header_tx BIGINT;
BEGIN
  SELECT creation_txid INTO header_tx FROM fame_live.payment_journals WHERE journal_id=NEW.journal_id;
  IF header_tx IS NULL OR header_tx <> txid_current() THEN
    RAISE EXCEPTION 'FAME_LIVE_PAYMENT_JOURNAL_CLOSED' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS payment_lines_same_tx ON fame_live.payment_journal_lines;
CREATE TRIGGER payment_lines_same_tx BEFORE INSERT ON fame_live.payment_journal_lines
  FOR EACH ROW EXECUTE FUNCTION fame_live.payment_lines_same_tx();

CREATE OR REPLACE FUNCTION fame_live.payment_journal_balance()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE n INTEGER; deb NUMERIC; cred NUMERIC;
BEGIN
  SELECT count(*),coalesce(sum(debit_minor),0),coalesce(sum(credit_minor),0)
    INTO n,deb,cred FROM fame_live.payment_journal_lines WHERE journal_id=NEW.journal_id;
  IF n < 2 OR deb <= 0 OR deb <> cred THEN
    RAISE EXCEPTION 'FAME_LIVE_PAYMENT_JOURNAL_UNBALANCED' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS payment_journal_balanced ON fame_live.payment_journals;
CREATE CONSTRAINT TRIGGER payment_journal_balanced
  AFTER INSERT ON fame_live.payment_journals DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION fame_live.payment_journal_balance();

COMMIT;

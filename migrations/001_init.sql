-- FAME F1E.1: synthetic-only authoritative ledger bootstrap.
-- Run as a DB admin on a dedicated database. Requires PostgreSQL >= 14.
-- Does not support real money, payment-provider events, or escrow.
BEGIN;
CREATE SCHEMA IF NOT EXISTS fame_finance;

CREATE TABLE fame_finance.actor_grants (
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('READ_TEST','POST_TEST','REVERSE_TEST')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, project_id, actor_id, permission)
);

CREATE TABLE fame_finance.journals (
  journal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  created_by_actor TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash CHAR(64) NOT NULL,
  currency_code TEXT NOT NULL CHECK (currency_code='USD'),
  journal_kind TEXT NOT NULL CHECK (journal_kind IN ('ORIGINAL','REVERSAL')),
  reverses_journal_id UUID REFERENCES fame_finance.journals(journal_id) ON DELETE RESTRICT,
  posting_status TEXT NOT NULL CHECK (posting_status='POSTED_TEST'),
  commit_receipt UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  creation_txid BIGINT NOT NULL DEFAULT txid_current(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT reversal_shape CHECK (
    (journal_kind='ORIGINAL' AND reverses_journal_id IS NULL) OR
    (journal_kind='REVERSAL' AND reverses_journal_id IS NOT NULL)
  ),
  UNIQUE (tenant_id, project_id, idempotency_key)
);
CREATE UNIQUE INDEX once_per_original_journal
  ON fame_finance.journals (reverses_journal_id)
  WHERE reverses_journal_id IS NOT NULL;
CREATE INDEX journals_project_idx ON fame_finance.journals(tenant_id,project_id,created_at);

CREATE TABLE fame_finance.journal_lines (
  journal_id UUID NOT NULL REFERENCES fame_finance.journals(journal_id) ON DELETE RESTRICT,
  line_number INTEGER NOT NULL CHECK (line_number BETWEEN 1 AND 100),
  account_code TEXT NOT NULL CHECK (account_code ~ '^[A-Z][A-Z0-9_]{2,39}$'),
  debit_minor BIGINT NOT NULL CHECK (debit_minor BETWEEN 0 AND 1000000000000),
  credit_minor BIGINT NOT NULL CHECK (credit_minor BETWEEN 0 AND 1000000000000),
  PRIMARY KEY (journal_id,line_number),
  CONSTRAINT exactly_one_side CHECK (
    (debit_minor > 0 AND credit_minor=0) OR (credit_minor > 0 AND debit_minor=0)
  )
);

CREATE TABLE fame_finance.outbox_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  journal_id UUID NOT NULL REFERENCES fame_finance.journals(journal_id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (event_type='TEST_JOURNAL_POSTED'),
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at TIMESTAMPTZ NULL,
  delivery_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX outbox_unpublished_idx ON fame_finance.outbox_events(created_at) WHERE delivered_at IS NULL;

CREATE TABLE fame_finance.request_nonces (
  nonce TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX request_nonces_created_at_idx ON fame_finance.request_nonces(created_at);
-- Cleanup old nonces with a scheduled protected DB job (not exposed by API).

CREATE OR REPLACE FUNCTION fame_finance.prevent_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'FAME_IMMUTABLE_LEDGER_RECORD' USING ERRCODE='23514';
END $$;

CREATE TRIGGER journals_immutable BEFORE UPDATE OR DELETE ON fame_finance.journals
FOR EACH ROW EXECUTE FUNCTION fame_finance.prevent_change();
CREATE TRIGGER lines_immutable BEFORE UPDATE OR DELETE ON fame_finance.journal_lines
FOR EACH ROW EXECUTE FUNCTION fame_finance.prevent_change();

-- A journal's lines must be created in the exact transaction that created the header.
-- This prevents later INSERTs from modifying previously committed journals.
CREATE OR REPLACE FUNCTION fame_finance.same_tx_lines_only() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE header_tx BIGINT;
BEGIN
  SELECT creation_txid INTO header_tx FROM fame_finance.journals WHERE journal_id=NEW.journal_id;
  IF header_tx IS NULL OR header_tx <> txid_current() THEN
    RAISE EXCEPTION 'FAME_JOURNAL_ALREADY_COMMITTED' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER insert_lines_during_creation_only BEFORE INSERT ON fame_finance.journal_lines
FOR EACH ROW EXECUTE FUNCTION fame_finance.same_tx_lines_only();

-- Deferred so rows may be inserted after the header in one transaction.
-- The COMMIT fails if header is empty or debits != credits.
CREATE OR REPLACE FUNCTION fame_finance.check_balanced_journal() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE n INTEGER; deb NUMERIC; cred NUMERIC;
BEGIN
  SELECT count(*), coalesce(sum(debit_minor),0), coalesce(sum(credit_minor),0)
    INTO n, deb, cred
    FROM fame_finance.journal_lines WHERE journal_id=NEW.journal_id;
  IF n < 2 OR n > 100 OR deb <= 0 OR deb <> cred OR deb > 1000000000000 THEN
    RAISE EXCEPTION 'FAME_JOURNAL_UNBALANCED_OR_INCOMPLETE' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER validate_journal_on_commit
  AFTER INSERT ON fame_finance.journals
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION fame_finance.check_balanced_journal();

COMMIT;

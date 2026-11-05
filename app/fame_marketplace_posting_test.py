"""FAME F1 marketplace journal posting primitive — TEST ONLY.

Backend/internal use ONLY. This is not a web endpoint and DOES NOT verify
Stripe payments. A separate trusted reconciler must establish payment truth
before it may call this function. Never expose this function to a browser.

The caller supplies its own dedicated ledger-poster psycopg connection (not
neondb_owner). On a successful call it commits an immutable, balanced journal
and its finance outbox event in ONE DB transaction.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

MARKETPLACE_TENANT = "fame.marketplace.test"
MARKETPLACE_PROJECT = "marketplace.orders"
POSTER_ACTOR = "fame.stripe.reconciler.test"
ACCOUNT_CLEARING = "STRIPE_CLEARING"
ACCOUNT_SELLER = "SELLER_PAYABLE"
ACCOUNT_FEE = "FAME_FEE_REVENUE"
MONEY_LIMIT = 10_000_000  # 100,000.00 USD; existing TEST checkout cap


class PostingRejected(Exception):
    """A posting did not satisfy the TEST financial authority contract."""


@dataclass(frozen=True)
class VerifiedMarketplacePayment:
    """Internal-only evidence after separate verified-Stripe reconciliation.

    This value type is NOT a proof of verification on its own. Do not populate
    from user-supplied JSON or unvalidated webhook intake metadata.
    """

    order_id: uuid.UUID
    payment_intent_id: str
    amount_minor: int
    fee_minor: int
    currency: str = "USD"


def _canonical_instruction(e: VerifiedMarketplacePayment) -> tuple[str, str]:
    if not isinstance(e, VerifiedMarketplacePayment):
        raise PostingRejected("FAME_POSTING_EVIDENCE_TYPE_INVALID")
    if not isinstance(e.order_id, uuid.UUID):
        raise PostingRejected("FAME_POSTING_ORDER_ID_INVALID")
    if (not isinstance(e.payment_intent_id, str) or
            re.fullmatch(r"pi_[A-Za-z0-9]{4,128}", e.payment_intent_id) is None):
        raise PostingRejected("FAME_POSTING_PAYMENT_INTENT_INVALID")
    if e.currency != "USD":
        raise PostingRejected("FAME_POSTING_CURRENCY_INVALID")
    if (type(e.amount_minor) is not int or not (50 <= e.amount_minor <= MONEY_LIMIT) or
            type(e.fee_minor) is not int or e.fee_minor < 0 or
            e.fee_minor >= e.amount_minor):
        raise PostingRejected("FAME_POSTING_AMOUNTS_INVALID")
    # This function is ONLY for a marketplace payment; fee policy is 5%, half-up.
    expected_fee = (e.amount_minor * 500 + 5_000) // 10_000
    if e.fee_minor != expected_fee:
        raise PostingRejected("FAME_POSTING_FEE_MISMATCH")
    canonical = json.dumps({
        "policy": "FAME_FEE_V1", "kind": "MARKETPLACE_PAID_TEST",
        "tenant": MARKETPLACE_TENANT, "project": MARKETPLACE_PROJECT,
        "order_id": str(e.order_id), "payment_intent_id": e.payment_intent_id,
        "amount_minor": e.amount_minor, "fee_minor": e.fee_minor,
        "currency": "USD",
    }, separators=(",", ":"), sort_keys=True)
    return "marketplace-paid:" + str(e.order_id), hashlib.sha256(canonical.encode()).hexdigest()


def _journal_outbox_payload(e: VerifiedMarketplacePayment, journal_id: str) -> str:
    return json.dumps({
        "kind": "MARKETPLACE_PAID_TEST", "orderId": str(e.order_id),
        "journalId": journal_id, "paymentIntentId": e.payment_intent_id,
        "amountMinor": e.amount_minor, "feeMinor": e.fee_minor,
        "currency": e.currency,
    }, sort_keys=True, separators=(",", ":"))


def post_marketplace_paid_test(conn: Any, evidence: VerifiedMarketplacePayment) -> dict:
    """Post one internally verified marketplace payment, or return prior receipt.

    Requires the connection to be dedicated to this operation, with no open
    transaction at entry. The DB role must not own schemas/tables/triggers.
    This function commits or rolls back the transaction and leaves the conn open.

    For TEST use only. Actual payment verification, lifecycle reconciliation,
    buyer/seller authorization and refund handling are NOT implemented here.
    """
    key, request_hash = _canonical_instruction(evidence)
    journal_id = str(uuid.uuid4())
    receipt = str(uuid.uuid4())
    try:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM fame_finance.actor_grants
                    WHERE tenant_id=%s AND project_id=%s AND actor_id=%s
                      AND permission='POST_TEST' AND active=true
                """, (MARKETPLACE_TENANT, MARKETPLACE_PROJECT, POSTER_ACTOR))

                if cur.fetchone() is None:
                    raise PostingRejected("FAME_MARKETPLACE_POST_GRANT_MISSING")

                # Unique (tenant_id,project_id,idempotency_key) prevents
                # duplicates across workers. Under contention, ON CONFLICT
                # blocks until first insert commits or rolls back.
                cur.execute("""
                    INSERT INTO fame_finance.journals
                    (journal_id,tenant_id,project_id,created_by_actor,
                     idempotency_key,request_hash,currency_code,journal_kind,
                     posting_status,commit_receipt)
                    VALUES (%s,%s,%s,%s,%s,%s,'USD','ORIGINAL','POSTED_TEST',%s)
                    ON CONFLICT (tenant_id,project_id,idempotency_key) DO NOTHING
                    RETURNING journal_id::text,commit_receipt::text
                """, (journal_id, MARKETPLACE_TENANT, MARKETPLACE_PROJECT,
                      POSTER_ACTOR, key, request_hash, receipt))
                created = cur.fetchone()
                if created is None:
                    cur.execute("""
                        SELECT journal_id::text,commit_receipt::text,request_hash,
                               journal_kind,posting_status
                        FROM fame_finance.journals
                        WHERE tenant_id=%s AND project_id=%s AND idempotency_key=%s
                    """, (MARKETPLACE_TENANT, MARKETPLACE_PROJECT, key))
                    existing = cur.fetchone()
                    if not existing:
                        raise PostingRejected("FAME_POSTING_RETRY_NOT_FOUND")
                    prior_id, prior_receipt, prior_hash, kind, status = existing
                    if (prior_hash.strip() != request_hash or kind != "ORIGINAL"
                            or status != "POSTED_TEST"):
                        raise PostingRejected("FAME_POSTING_IDEMPOTENCY_CONFLICT")
                    return {"state": "ALREADY_POSTED_TEST", "journalId": prior_id,
                            "commitReceipt": prior_receipt}

                seller_minor = evidence.amount_minor - evidence.fee_minor
                cur.executemany("""
                    INSERT INTO fame_finance.journal_lines
                    (journal_id,line_number,account_code,debit_minor,credit_minor)
                    VALUES (%s,%s,%s,%s,%s)
                """, [
                    (journal_id, 1, ACCOUNT_CLEARING, evidence.amount_minor, 0),
                    (journal_id, 2, ACCOUNT_SELLER, 0, seller_minor),
                    (journal_id, 3, ACCOUNT_FEE, 0, evidence.fee_minor),
                ])
                cur.execute("""
                    INSERT INTO fame_finance.outbox_events
                    (journal_id,event_type,payload)
                    VALUES (%s,'TEST_JOURNAL_POSTED',%s::jsonb)
                """, (journal_id, _journal_outbox_payload(evidence, journal_id)))
                # The deferred balance trigger runs on transaction commit.
        return {"state": "POSTED_TEST", "journalId": journal_id,
                "commitReceipt": receipt}
    except Exception:
        # psycopg transaction context rolls back on exception. Do not attempt
        # to repair immutable accounting records with UPDATE/DELETE.
        raise

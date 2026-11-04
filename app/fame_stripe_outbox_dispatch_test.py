"""FAME F1 Stripe TEST financial outbox dispatcher — INTERNAL, not a route.

Uses two *different*, dedicated DB connections with different least-privilege
roles. The Stripe DB transaction locks an outbox event. The journal poster
commits independently; crash before delivery receipt is retry-safe because
ledger posting is deterministic per order.

No scheduling/queue integration provided. Refuses refunds and unknown payloads.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any


from app.fame_marketplace_posting_test import (VerifiedMarketplacePayment,
                                           post_marketplace_paid_test)


class OutboxRejected(Exception):
    pass


def _verify_payload(payload: Any, digest: str, order_id: str, stored_pi: str,
                    amount: int, fee: int, seller_account: str) -> VerifiedMarketplacePayment:
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise OutboxRejected('FAME_OUTBOX_PAYLOAD_INVALID')
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    if hashlib.sha256(raw.encode()).hexdigest() != str(digest).strip():
        raise OutboxRejected('FAME_OUTBOX_PAYLOAD_HASH_MISMATCH')
    if payload.get('schema') != 'FAME_MARKETPLACE_PAID_TEST_V1':
        raise OutboxRejected('FAME_OUTBOX_SCHEMA_INVALID')
    if (payload.get('order_id') != order_id or
        payload.get('stripe_payment_intent_id') != stored_pi or
        payload.get('stripe_account_id') != seller_account or
        type(payload.get('amount_minor')) is not int or payload['amount_minor'] != amount or
        type(payload.get('fee_minor')) is not int or payload['fee_minor'] != fee or
        payload.get('currency') != 'USD'):
        raise OutboxRejected('FAME_OUTBOX_ORDER_MISMATCH')
    if not re.fullmatch(r'pi_[A-Za-z0-9_]{4,128}', stored_pi):
        raise OutboxRejected('FAME_OUTBOX_PAYMENT_INTENT_INVALID')
    return VerifiedMarketplacePayment(order_id=uuid.UUID(order_id),
                                      payment_intent_id=stored_pi, amount_minor=amount,
                                      fee_minor=fee, currency='USD')


def dispatch_one_paid(stripe_conn: Any, ledger_conn: Any,
                      *, provider_event_id: str) -> dict:
    """Only for VERIFIED, STAGED `MARKETPLACE_PAID` events. One at a time.

    `stripe_conn`: role with SELECT/UPDATE delivery fields on outbox, read
    orders/sellers/intake. `ledger_conn`: distinct `fame_ledger_poster` role.
    Both should be idle connections; do not expose this function as an API.
    """
    if not isinstance(provider_event_id, str) or not re.fullmatch(r'evt_[A-Za-z0-9_]{4,128}', provider_event_id):
        raise OutboxRejected('FAME_OUTBOX_EVENT_ID_INVALID')
    with stripe_conn.transaction():
        with stripe_conn.cursor() as cur:
            cur.execute('''SELECT f.order_id::text,f.event_type,f.payload,f.payload_hash,
                f.delivered_at,f.ledger_journal_id::text,mo.status,
                mo.stripe_payment_intent_id,mo.amount_minor,mo.fee_minor,
                mo.currency,sa.stripe_account_id,ie.processing_status
                FROM fame_stripe.financial_outbox_test f
                JOIN fame_stripe.marketplace_orders mo ON mo.order_id=f.order_id
                JOIN fame_stripe.seller_accounts sa ON sa.seller_key=mo.seller_key
                JOIN fame_stripe.intake_events ie ON ie.stripe_event_id=f.provider_event_id
                WHERE f.provider_event_id=%s
                FOR UPDATE OF f''', (provider_event_id,))
            row = cur.fetchone()
            if row is None:
                raise OutboxRejected('FAME_OUTBOX_NOT_FOUND')
            (order_id,event_type,payload,digest,delivered_at,prior_journal,
             order_state,pi_id,amount,fee,currency,seller_account,intake_state) = row
            if event_type != 'MARKETPLACE_PAID' or order_state != 'PAID' \
                    or currency != 'usd' or intake_state != 'PROCESSED':
                raise OutboxRejected('FAME_OUTBOX_NOT_READY')
            if delivered_at is not None:
                if not prior_journal:
                    raise OutboxRejected('FAME_OUTBOX_DELIVERY_RECEIPT_MISSING')
                return {'state':'ALREADY_DELIVERED_TEST','journalId':prior_journal}
            proof = _verify_payload(payload,digest,order_id,pi_id,amount,fee,seller_account)
            # Committed ledger journal is immutable. If this Stripe transaction
            # subsequently fails, next delivery retry gets same journal receipt.
            posted = post_marketplace_paid_test(ledger_conn, proof)
            journal_id = posted['journalId']
            cur.execute('''UPDATE fame_stripe.financial_outbox_test
                SET ledger_journal_id=%s, delivered_at=now(),
                    delivery_attempts=delivery_attempts+1, last_error_code=NULL
                WHERE provider_event_id=%s AND delivered_at IS NULL''',
                (journal_id, provider_event_id))
            if cur.rowcount != 1:
                raise OutboxRejected('FAME_OUTBOX_DELIVERY_RACE')
            return {'state':'DELIVERED_TEST','journalId':journal_id,
                    'postingState':posted['state']}

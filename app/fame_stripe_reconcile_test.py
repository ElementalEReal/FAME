"""FAME F1 Stripe TEST reconciliation candidate — INTERNAL WORKER, not a route.

Safety model: a verified Stripe TEST Session+PaymentIntent is matched to a
persisted marketplace order and seller Connect mapping, then one transaction
sets order PAID, marks intake PROCESSED, and stages an outbox event. No ledger
posting here. Never call from the browser, checkout creation, or raw webhook.

The worker must use a restricted role for these operations. This module does
NOT authorize customer purchases or validate a live listing approval — those
are separate checkout gates. Refunds, disputes and thin events not supported.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any

SUPPORTED_EVENT_TYPES = frozenset({
    "checkout.session.completed", "checkout.session.async_payment_succeeded"
})
STRIPE_MINOR_MAX = 10_000_000


class ReconcileRejected(Exception):
    """Inconsistent, invalid, or unauthorized payment evidence."""


class ReconcileRetry(Exception):
    """Transient state; do not mark the event processed or failed permanently."""


def prop(obj: Any, name: str, default=None):
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def valid_stripe_id(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9_]{4,128}", value))


@dataclass(frozen=True)
class PaymentProof:
    order_id: uuid.UUID
    session_id: str
    payment_intent_id: str
    seller_account_id: str
    amount_minor: int
    fee_minor: int
    currency: str


def verify_payment(session: Any, intent: Any, *, expected_order_id: str,
                   expected_session_id: str, expected_seller_account: str,
                   expected_amount: int, expected_fee: int) -> PaymentProof:
    """Strict checks of Stripe resources fetched with service TEST credentials."""
    try:
        order_uuid = uuid.UUID(expected_order_id)
    except (ValueError, TypeError) as exc:
        raise ReconcileRejected('FAME_PROOF_ORDER_INVALID') from exc
    sid = prop(session, 'id')
    pi_id = prop(intent, 'id')
    if sid != expected_session_id or not valid_stripe_id(sid, 'cs_test_'):
        raise ReconcileRejected('FAME_PROOF_SESSION_MISMATCH')
    if not valid_stripe_id(pi_id, 'pi_'):
        raise ReconcileRejected('FAME_PROOF_INTENT_INVALID')
    if prop(session, 'livemode') is not False or prop(intent, 'livemode') is not False:
        raise ReconcileRejected('FAME_PROOF_NOT_TEST')
    if prop(session, 'mode') != 'payment' or prop(session, 'payment_status') != 'paid':
        raise ReconcileRetry('FAME_PROOF_NOT_PAID')
    if prop(intent, 'status') != 'succeeded':
        raise ReconcileRetry('FAME_PROOF_INTENT_NOT_SUCCEEDED')
    s_pi = prop(session, 'payment_intent')
    if prop(s_pi, 'id', s_pi) != pi_id:
        raise ReconcileRejected('FAME_PROOF_INTENT_MISMATCH')
    if not isinstance(expected_amount, int) or not 50 <= expected_amount <= STRIPE_MINOR_MAX:
        raise ReconcileRejected('FAME_PROOF_AMOUNT_INVALID')
    if not isinstance(expected_fee, int) or expected_fee != (expected_amount * 500 + 5000) // 10000:
        raise ReconcileRejected('FAME_PROOF_FEE_INVALID')
    if prop(session, 'amount_total') != expected_amount or prop(intent, 'amount') != expected_amount:
        raise ReconcileRejected('FAME_PROOF_AMOUNT_MISMATCH')
    if prop(intent, 'amount_received') != expected_amount:
        raise ReconcileRejected('FAME_PROOF_RECEIVED_MISMATCH')
    if prop(session, 'currency') != 'usd' or prop(intent, 'currency') != 'usd':
        raise ReconcileRejected('FAME_PROOF_CURRENCY_MISMATCH')
    if prop(prop(session, 'metadata', {}), 'fame_order_id') != str(order_uuid):
        raise ReconcileRejected('FAME_PROOF_SESSION_ORDER_MISMATCH')
    if prop(prop(intent, 'metadata', {}), 'fame_order_id') != str(order_uuid):
        raise ReconcileRejected('FAME_PROOF_INTENT_ORDER_MISMATCH')
    paydata = prop(intent, 'transfer_data', {}) or {}
    if prop(paydata, 'destination') != expected_seller_account:
        raise ReconcileRejected('FAME_PROOF_DESTINATION_MISMATCH')
    if prop(intent, 'application_fee_amount') != expected_fee:
        raise ReconcileRejected('FAME_PROOF_APPLICATION_FEE_MISMATCH')
    return PaymentProof(order_uuid, sid, pi_id, expected_seller_account,
                        expected_amount, expected_fee, 'USD')


def _outbox_payload(proof: PaymentProof) -> tuple[dict, str]:
    payload = {
        'schema': 'FAME_MARKETPLACE_PAID_TEST_V1', 'order_id': str(proof.order_id),
        'stripe_session_id': proof.session_id,
        'stripe_payment_intent_id': proof.payment_intent_id,
        'stripe_account_id': proof.seller_account_id,
        'amount_minor': proof.amount_minor, 'fee_minor': proof.fee_minor,
        'currency': 'USD',
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return payload, hashlib.sha256(raw.encode('utf-8')).hexdigest()


# Public helper retained for the existing app/tests/test_proof.py import.
# Same implementation and deterministic hash as the internal helper.
outbox_payload = _outbox_payload


def stage_paid_event(conn: Any, *, event_id: str, event_type: str,
                     stripe_client: Any) -> dict:
    """Worker-only entry point, using restricted Stripe DB role.

    An intake event MUST already have been signature-verified by webhook.
    Reads intake/order mapping, fetches authoritative TEST Stripe resources,
    and transactionally updates order/intake/outbox.

    Must be called with an idle, dedicated psycopg3 connection. This function
    does not create a journal and does not open a Stripe session.
    """
    if not valid_stripe_id(event_id, 'evt_') or event_type not in SUPPORTED_EVENT_TYPES:
        raise ReconcileRejected('FAME_RECON_EVENT_INVALID')

    # Read a non-authoritative snapshot first so no transaction lock is held
    # across Stripe API calls. Re-lock and compare in the committing transaction.
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute('''SELECT stripe_object_id, event_type, livemode, processing_status
                FROM fame_stripe.intake_events WHERE stripe_event_id=%s''', (event_id,))
            event_row = cur.fetchone()
    if not event_row:
        raise ReconcileRejected('FAME_RECON_UNVERIFIED_EVENT')
    object_id, stored_type, livemode, state = event_row
    if stored_type != event_type or livemode is not False or not valid_stripe_id(object_id, 'cs_test_'):
        raise ReconcileRejected('FAME_RECON_EVENT_ENVELOPE_INVALID')
    # Legacy webhook intake can be PROCESSED without an outbox record.
    # Do not equate that status with a staged financial event. All attempts,
    # including recovery, must re-verify payment evidence against Stripe TEST.
    if state not in ('RECEIVED', 'PROCESSED'):
        raise ReconcileRejected('FAME_RECON_EVENT_STATE_INVALID')

    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute('''SELECT mo.order_id::text,mo.amount_minor,mo.fee_minor,
                mo.currency,mo.status,mo.stripe_session_id,mo.stripe_payment_intent_id,
                sa.stripe_account_id
                FROM fame_stripe.marketplace_orders mo
                JOIN fame_stripe.seller_accounts sa ON mo.seller_key=sa.seller_key
                WHERE mo.stripe_session_id=%s''', (object_id,))
            order = cur.fetchone()
    if order is None:
        raise ReconcileRetry('FAME_RECON_ORDER_NOT_YET_LINKED')
    (order_id, amount, fee, currency, order_state, session_id, prior_pi, seller_account) = order
    if currency != 'usd' or order_state not in ('PENDING', 'PAID'):
        raise ReconcileRejected('FAME_RECON_ORDER_STATE_INVALID')

    # Stripe API GETs use server TEST credentials; NEVER trust data from event
    # metadata or a browser as payment proof.
    session = stripe_client.checkout.Session.retrieve(object_id)
    pi_ref = prop(session, 'payment_intent')
    pi_id = prop(pi_ref, 'id', pi_ref)
    if not valid_stripe_id(pi_id, 'pi_'):
        raise ReconcileRetry('FAME_RECON_MISSING_INTENT')
    intent = stripe_client.PaymentIntent.retrieve(pi_id)
    proof = verify_payment(session, intent,
        expected_order_id=order_id, expected_session_id=session_id,
        expected_seller_account=seller_account,
        expected_amount=amount, expected_fee=fee)
    if prior_pi and prior_pi != proof.payment_intent_id:
        raise ReconcileRejected('FAME_RECON_ORDER_INTENT_CONFLICT')
    payload, payload_hash = _outbox_payload(proof)

    with conn.transaction():
        with conn.cursor() as cur:
            # Lock exact event and order. No external network I/O inside tx.
            cur.execute('''SELECT event_type,stripe_object_id,processing_status,livemode
                FROM fame_stripe.intake_events WHERE stripe_event_id=%s FOR UPDATE''', (event_id,))
            live_event = cur.fetchone()
            if not live_event or live_event[:2] != (event_type, object_id) or live_event[3] is not False:
                raise ReconcileRejected('FAME_RECON_EVENT_CHANGED')
            if live_event[2] not in ('RECEIVED', 'PROCESSED'):
                raise ReconcileRejected('FAME_RECON_EVENT_ALREADY_HANDLED')
            cur.execute('''SELECT mo.amount_minor,mo.fee_minor,mo.currency,
                mo.status,mo.stripe_session_id,mo.stripe_payment_intent_id,
                sa.stripe_account_id FROM fame_stripe.marketplace_orders mo
                JOIN fame_stripe.seller_accounts sa ON mo.seller_key=sa.seller_key
                WHERE mo.order_id=%s FOR UPDATE OF mo''', (proof.order_id,))
            live = cur.fetchone()
            if not live or live[:3] != (amount, fee, 'usd') or live[3] not in ('PENDING','PAID') \
                    or live[4] != session_id or (live[5] and live[5] != proof.payment_intent_id) \
                    or live[6] != seller_account:
                raise ReconcileRejected('FAME_RECON_ORDER_CHANGED')
            cur.execute('''UPDATE fame_stripe.marketplace_orders
                SET status='PAID', stripe_payment_intent_id=%s, updated_at=now()
                WHERE order_id=%s AND status IN ('PENDING','PAID')''',
                (proof.payment_intent_id, proof.order_id))
            if cur.rowcount != 1:
                raise ReconcileRetry('FAME_RECON_ORDER_UPDATE_LOST')
            cur.execute('''INSERT INTO fame_stripe.financial_outbox_test
                (provider_event_id,order_id,event_type,payload,payload_hash)
                VALUES (%s,%s,'MARKETPLACE_PAID',%s::jsonb,%s)
                ON CONFLICT (provider_event_id) DO NOTHING''',
                (event_id, proof.order_id, json.dumps(payload), payload_hash))
            newly_staged = cur.rowcount == 1
            if not newly_staged:
                # A replay is valid only when the exact event and payload match.
                cur.execute('''SELECT order_id::text,event_type,payload_hash
                    FROM fame_stripe.financial_outbox_test WHERE provider_event_id=%s''', (event_id,))
                prev = cur.fetchone()
                if not prev or prev != (str(proof.order_id), 'MARKETPLACE_PAID', payload_hash):
                    raise ReconcileRejected('FAME_RECON_OUTBOX_CONFLICT')
            if live_event[2] == 'RECEIVED':
                cur.execute('''UPDATE fame_stripe.intake_events SET processing_status='PROCESSED'
                    WHERE stripe_event_id=%s AND processing_status='RECEIVED' ''', (event_id,))
                if cur.rowcount != 1:
                    raise ReconcileRetry('FAME_RECON_EVENT_CLAIM_LOST')
            # Legacy PROCESSED status is preserved; recovered outbox was
            # inserted only after independent Stripe verification and row locks.
    return {'state': 'STAGED_TEST' if newly_staged else 'ALREADY_STAGED_TEST',
            'eventId': event_id, 'orderId': str(proof.order_id),
            'paymentIntentId': proof.payment_intent_id}

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


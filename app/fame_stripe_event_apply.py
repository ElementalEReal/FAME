"""FAME Stripe TEST: atomic verified webhook observations and optional financial outbox.

No direct ledger writes or fulfillment. Enable FAME_STRIPE_FINANCE_OUTBOX_ENABLED=1
ONLY after installing stripe_test/003_verified_financial_outbox.sql on Neon TEST.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os

log = logging.getLogger('fame.stripe.marketplace')


def _outbox_enabled() -> bool:
    return os.getenv('FAME_STRIPE_FINANCE_OUTBOX_ENABLED', '0') == '1' and os.getenv('FAME_STRIPE_MODE') == 'test'


def _enqueue(cur, event, *, order_id: str, event_type: str) -> None:
    # Source of truth is the committed order row; never use client amount or price.
    cur.execute('''SELECT order_id::text,listing_id,buyer_key,seller_key,amount_minor,
                          fee_minor,refunded_minor,currency,stripe_session_id,stripe_payment_intent_id
                   FROM fame_stripe.marketplace_orders WHERE order_id::text=%s''',(order_id,))
    record = cur.fetchone()
    if not record or not record[8] or not record[9]:
        raise RuntimeError('Verified financial event lacks FAME order or Stripe IDs')
    keys=('orderId','listingId','buyerKey','sellerKey','amountMinor','feeMinor',
          'refundedMinor','currencyCode','stripeSessionId','stripePaymentIntentId')
    payload=dict(zip(keys,record))
    payload['providerEventId']=event['id']
    payload['eventType']=event_type
    payload['currencyCode']=str(payload['currencyCode']).upper()
    # Test only. Do not deliver events tied to live Stripe objects.
    if event.get('livemode') is not False or not payload['stripeSessionId'].startswith('cs_test_'):
        raise RuntimeError('Refusing non-test provider evidence')
    stable=json.dumps(payload,sort_keys=True,separators=(',',':')).encode('utf8')
    digest=hashlib.sha256(stable).hexdigest()
    cur.execute('''INSERT INTO fame_stripe.financial_outbox_test
                   (provider_event_id,order_id,event_type,payload,payload_hash)
                   VALUES (%s,%s,%s,%s::jsonb,%s)
                   ON CONFLICT(provider_event_id) DO NOTHING''',
                (event['id'],order_id,event_type,stable.decode('utf8'),digest))
    if cur.rowcount!=1:
        raise RuntimeError('Verified Stripe event unexpectedly reused in financial outbox')


def apply_verified_event(cur,event):
    kind=event.get('type')
    obj=(event.get('data') or {}).get('object') or {}
    if kind=='account.updated':
        account_id=obj.get('id')
        if isinstance(account_id,str):
            cur.execute('''UPDATE fame_stripe.seller_accounts
               SET charges_enabled=%s,payouts_enabled=%s,details_submitted=%s,updated_at=now()
               WHERE stripe_account_id=%s''',
                (bool(obj.get('charges_enabled')),bool(obj.get('payouts_enabled')),
                 bool(obj.get('details_submitted')),account_id))

    elif kind in ('checkout.session.completed','checkout.session.async_payment_succeeded'):
        order_id=(obj.get('metadata') or {}).get('fame_order_id')
        if not order_id or obj.get('payment_status')!='paid':
            return
        cur.execute('''SELECT stripe_session_id,amount_minor,currency,status
                       FROM fame_stripe.marketplace_orders
                       WHERE order_id::text=%s FOR UPDATE''',(order_id,))
        row=cur.fetchone()
        if not row:
            raise RuntimeError('Unknown FAME order in verified Checkout event')
        sid,amount,currency,status=row
        if sid!=obj.get('id') or amount!=obj.get('amount_total') or currency!=obj.get('currency'):
            raise RuntimeError('Stripe Checkout order mismatch')
        if status in ('PENDING','CREATING'):
            pi=obj.get('payment_intent')
            if _outbox_enabled() and (not isinstance(pi,str) or not pi.startswith('pi_')):
                raise RuntimeError('Stripe Checkout payment intent evidence missing')
            cur.execute('''UPDATE fame_stripe.marketplace_orders
                           SET status='PAID',stripe_payment_intent_id=%s,updated_at=now()
                           WHERE order_id::text=%s''',(pi,order_id))
            if _outbox_enabled():
                _enqueue(cur,event,order_id=order_id,event_type='MARKETPLACE_PAID')

    elif kind=='checkout.session.async_payment_failed':
        order_id=(obj.get('metadata') or {}).get('fame_order_id')
        if order_id:
            cur.execute('''UPDATE fame_stripe.marketplace_orders
               SET status='FAILED',updated_at=now() WHERE order_id::text=%s AND stripe_session_id=%s
               AND status='PENDING' ''',(order_id,obj.get('id')))

    elif kind=='charge.refunded':
        pi=obj.get('payment_intent')
        amount_refunded=obj.get('amount_refunded')
        if not isinstance(pi,str) or not isinstance(amount_refunded,int) or type(amount_refunded) is bool:
            return
        cur.execute('''SELECT order_id::text,amount_minor,refunded_minor,status
                       FROM fame_stripe.marketplace_orders
                       WHERE stripe_payment_intent_id=%s FOR UPDATE''',(pi,))
        row=cur.fetchone()
        if not row:
            # Not all Stripe charges are FAME marketplace orders.
            return
        order_id,gross,previous,status=row
        if amount_refunded<0 or amount_refunded>gross:
            raise RuntimeError('Stripe cumulative refund exceeds FAME order')
        if status not in ('PAID','PARTIALLY_REFUNDED','REFUNDED'):
            # Fail closed and retry rather than applying a refund without a paid order.
            raise RuntimeError('FAME order not yet recognized as paid')
        if amount_refunded>previous:
            cur.execute('''UPDATE fame_stripe.marketplace_orders
                          SET refunded_minor=%s,
                              status=CASE WHEN %s=amount_minor THEN 'REFUNDED'
                                          ELSE 'PARTIALLY_REFUNDED' END,
                              updated_at=now()
                          WHERE order_id::text=%s''',
                        (amount_refunded,amount_refunded,order_id))
            if _outbox_enabled():
                _enqueue(cur,event,order_id=order_id,event_type='MARKETPLACE_REFUND_UPDATED')
        # Older out-of-order cumulative observations cannot reduce refunded amount.
        # Actual Stripe fee/transfer reversals require independent reconciliation later.

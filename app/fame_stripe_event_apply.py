"""Apply only verified Stripe webhook events to FAME TEST marketplace read models.
No financial ledger posting or automatic product delivery is performed here.
"""
import logging

log = logging.getLogger('fame.stripe.marketplace')


def apply_verified_event(cur, event):
    kind = event.get('type')
    obj = (event.get('data') or {}).get('object') or {}
    if kind == 'account.updated':
        account_id = obj.get('id')
        if isinstance(account_id, str):
            cur.execute('''UPDATE fame_stripe.seller_accounts
               SET charges_enabled=%s,payouts_enabled=%s,details_submitted=%s,updated_at=now()
               WHERE stripe_account_id=%s''',
                (bool(obj.get('charges_enabled')),bool(obj.get('payouts_enabled')),
                 bool(obj.get('details_submitted')),account_id))
    elif kind in ('checkout.session.completed','checkout.session.async_payment_succeeded'):
        order_id = (obj.get('metadata') or {}).get('fame_order_id')
        if not order_id:
            return  # CLI-generated events don't represent a real FAME order.
        if obj.get('payment_status') != 'paid':
            return  # Delayed payment; await async_payment_succeeded.
        cur.execute('''SELECT stripe_session_id,amount_minor,currency,status
                       FROM fame_stripe.marketplace_orders
                       WHERE order_id::text=%s FOR UPDATE''', (order_id,))
        row = cur.fetchone()
        if not row:
            raise RuntimeError('Unknown FAME order in verified Checkout event')
        sid, amount, currency, status = row
        if sid != obj.get('id') or amount != obj.get('amount_total') or currency != obj.get('currency'):
            raise RuntimeError('Stripe Checkout order mismatch')
        if status in ('PENDING','CREATING'):
            cur.execute('''UPDATE fame_stripe.marketplace_orders
                           SET status='PAID', stripe_payment_intent_id=%s, updated_at=now()
                           WHERE order_id::text=%s''', (obj.get('payment_intent'),order_id))
    elif kind == 'checkout.session.async_payment_failed':
        order_id = (obj.get('metadata') or {}).get('fame_order_id')
        if order_id:
            cur.execute('''UPDATE fame_stripe.marketplace_orders
               SET status='FAILED',updated_at=now() WHERE order_id::text=%s AND stripe_session_id=%s
               AND status='PENDING' ''', (order_id,obj.get('id')))
    elif kind == 'charge.refunded':
        pi = obj.get('payment_intent')
        if not pi:
            return
        amount_refunded = obj.get('amount_refunded')
        if not isinstance(amount_refunded,int) or amount_refunded < 0:
            return
        cur.execute('''UPDATE fame_stripe.marketplace_orders SET
                  refunded_minor=LEAST(amount_minor,%s),
                  status=CASE WHEN %s>=amount_minor THEN 'REFUNDED'
                              WHEN %s>0 THEN 'PARTIALLY_REFUNDED' ELSE status END,
                  updated_at=now()
                  WHERE stripe_payment_intent_id=%s''',
                  (amount_refunded,amount_refunded,amount_refunded,pi))
        # Financial reversal fees and transfer reversals are NOT inferred here.

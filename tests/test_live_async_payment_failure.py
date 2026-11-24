"""Fail-closed regression tests for signed LIVE async-payment-failed events."""
import hashlib
import unittest
from uuid import uuid4
from app.live_settlement import SettlementRejected, event_facts, apply_live_event, SUPPORTED


def evt(oid, *, kind='checkout.session.async_payment_failed', eid='evt_live_failed_1',
        session='cs_live_123', pi='pi_123', amount=2500, status='unpaid', live=True):
    return {'id':eid, 'type':kind, 'livemode':live,
            'data':{'object':{'id':session, 'metadata':{'fame_order_id':str(oid)},
                              'payment_intent':pi, 'amount_total':amount,
                              'currency':'usd', 'payment_status':status}}}


class Cursor:
    def __init__(self, oid, *, state='PENDING', existing_pi=None, existing_hash=None,
                 session='cs_live_123', amount=2500, rowcount=1):
        self.oid, self.state, self.existing_pi = oid, state, existing_pi
        self.existing_hash, self.session, self.amount = existing_hash, session, amount
        self.rowcount, self.statements, self.result = rowcount, [], None
    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        flat = ' '.join(sql.split())
        if flat.startswith('SELECT event_hash'):
            self.result = (self.existing_hash,) if self.existing_hash else None
        elif flat.startswith('SELECT order_id, state, stripe_session_id'):
            self.result = (self.oid, self.state, self.session, self.existing_pi,
                           self.amount, 125, 'usd')
        elif flat.startswith('SELECT order_id,state,amount_minor,refunded_minor'):
            self.result = (self.oid, self.state, self.amount, 0)
        else:
            self.result = None
    def fetchone(self):
        return self.result
    def contains(self, fragment):
        return any(fragment in q for q, _ in self.statements)


class AsyncFailureTests(unittest.TestCase):
    def setUp(self):
        self.oid = uuid4()
    def test_registered(self):
        self.assertIn('checkout.session.async_payment_failed', SUPPORTED)
    def test_failure_parses_as_failed_not_paid(self):
        self.assertEqual(event_facts(evt(self.oid))['kind'], 'FAILED')
    def test_payment_status_must_be_unpaid(self):
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_EVIDENCE_INVALID'):
            event_facts(evt(self.oid, status='paid'))
    def test_live_mode_required(self):
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_EVENT_MODE_INVALID'):
            event_facts(evt(self.oid, live=False))
    def test_requires_pi(self):
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_EVIDENCE_INVALID'):
            event_facts(evt(self.oid, pi=None))
    def test_pending_becomes_failed_with_no_journal(self):
        c = Cursor(self.oid)
        self.assertEqual(apply_live_event(c, evt(self.oid), b'raw'), 'applied')
        self.assertTrue(c.contains("SET state='FAILED'"))
        self.assertFalse(c.contains('INSERT INTO fame_live.payment_journals'))
        self.assertTrue(c.contains('INSERT INTO fame_live.provider_events'))
        update = next(p for q, p in c.statements if "SET state='FAILED'" in q)
        self.assertEqual(update, ('pi_123', self.oid))
    def test_failure_replay_deduplicates(self):
        c = Cursor(self.oid, existing_hash=hashlib.sha256(b'raw').hexdigest())
        self.assertEqual(apply_live_event(c, evt(self.oid), b'raw'), 'duplicate')
        self.assertEqual(len(c.statements), 1)
    def test_multiple_failures_same_pi_are_idempotent(self):
        c = Cursor(self.oid, state='FAILED', existing_pi='pi_123')
        self.assertEqual(apply_live_event(c, evt(self.oid, eid='evt_live_fail_2'), b'raw'), 'applied')
        self.assertFalse(c.contains('UPDATE fame_live.purchase_intents'))
    def test_late_failure_does_not_downgrade_paid(self):
        c = Cursor(self.oid, state='PAID', existing_pi='pi_123')
        self.assertEqual(apply_live_event(c, evt(self.oid), b'raw'), 'applied')
        self.assertFalse(c.contains('UPDATE fame_live.purchase_intents'))
        self.assertTrue(c.contains('INSERT INTO fame_live.provider_events'))
    def test_wrong_payment_intent_rejected(self):
        c = Cursor(self.oid, state='PAID', existing_pi='pi_other')
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_ORDER_MISMATCH'):
            apply_live_event(c, evt(self.oid), b'raw')
    def test_wrong_session_rejected(self):
        c = Cursor(self.oid, session='cs_live_other')
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_ORDER_MISMATCH'):
            apply_live_event(c, evt(self.oid), b'raw')
    def test_failure_then_success_requires_manual_reconciliation(self):
        c = Cursor(self.oid, state='FAILED', existing_pi='pi_123')
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_STATE_INVALID'):
            apply_live_event(c, evt(self.oid, kind='checkout.session.async_payment_succeeded',
                                    status='paid'), b'raw')
    def test_invalid_starting_state_rejected(self):
        c = Cursor(self.oid, state='CREATING')
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_FAILURE_STATE_INVALID'):
            apply_live_event(c, evt(self.oid), b'raw')
    def test_guarded_update_rowcount_required(self):
        c = Cursor(self.oid, rowcount=0)
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_FAILURE_STATE_CONFLICT'):
            apply_live_event(c, evt(self.oid), b'raw')
    def test_mismatched_amount_rejected(self):
        c = Cursor(self.oid, amount=4000)
        with self.assertRaisesRegex(SettlementRejected, 'LIVE_PAYMENT_ORDER_MISMATCH'):
            apply_live_event(c, evt(self.oid), b'raw')

if __name__ == '__main__':
    unittest.main()

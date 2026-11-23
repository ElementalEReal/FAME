import hashlib
import os
import sys
import types
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.live_settlement import SettlementRejected, event_facts, apply_live_event
from app.live_stripe_webhook import verify_live_signature


def paid_event(order_id, *, eid='evt_live_1', sid='cs_live_123', amount=2500, pi='pi_123'):
    return {'id':eid,'type':'checkout.session.completed','livemode':True,
            'data': {'object': {'id':sid, 'metadata':{'fame_order_id':str(order_id)},
                   'payment_status':'paid','currency':'usd','amount_total':amount,
                   'payment_intent':pi}}}


def refund_event(*, eid='evt_live_ref_1', cumulative=500):
    return {'id':eid,'type':'charge.refunded','livemode':True,
            'data':{'object':{'id':'ch_123', 'currency':'usd',
                              'payment_intent':'pi_123','amount_refunded':cumulative}}}


class FakeCursor:
    def __init__(self, order, state='PENDING', prior_pi=None, refund=0, previous_hash=None):
        self.order, self.state, self.prior_pi, self.refund = order, state, prior_pi, refund
        self.previous_hash = previous_hash
        self.queries = []
        self.rowcount = 1
        self._result = None
    def execute(self, sql, params=None):
        self.queries.append((sql, params))
        normalized = ' '.join(sql.split())
        if normalized.startswith('SELECT event_hash'):
            self._result = (self.previous_hash,) if self.previous_hash else None
        elif normalized.startswith('SELECT order_id, state, stripe_session_id'):
            self._result = (self.order,self.state,'cs_live_123',self.prior_pi,2500,125,'usd')
        elif normalized.startswith('SELECT order_id,state,amount_minor,refunded_minor'):
            self._result = (self.order,self.state,2500,self.refund)
        elif normalized.startswith('UPDATE fame_live.purchase_intents'):
            self._result = None
        else:
            self._result = None
    def fetchone(self):
        return self._result


class SettlementTests(unittest.TestCase):
    def setUp(self): self.oid = uuid4()
    def test_live_paid_facts(self):
        self.assertEqual(event_facts(paid_event(self.oid))['order_id'],self.oid)
    def test_test_mode_rejected(self):
        e=paid_event(self.oid);e['livemode']=False
        with self.assertRaises(SettlementRejected): event_facts(e)
    def test_connect_scoped_rejected(self):
        e=paid_event(self.oid);e['account']='acct_123'
        with self.assertRaises(SettlementRejected): event_facts(e)
    def test_missing_payment_intent_rejected(self):
        with self.assertRaises(SettlementRejected): event_facts(paid_event(self.oid,pi=None))
    def test_paid_journal_balanced_and_event_inserted(self):
        cur=FakeCursor(self.oid)
        self.assertEqual(apply_live_event(cur,paid_event(self.oid),b'raw'), 'applied')
        lines=[p for s,p in cur.queries if 'INSERT INTO fame_live.payment_journal_lines' in s]
        self.assertEqual(len(lines),3)
        self.assertEqual(sum(x[3] for x in lines),2500)
        self.assertEqual(sum(x[4] for x in lines),2500)
        self.assertTrue(any('INSERT INTO fame_live.provider_events' in s for s,p in cur.queries))
    def test_duplicate_same_event_no_second_journal(self):
        cur=FakeCursor(self.oid,previous_hash=hashlib.sha256(b'raw').hexdigest())
        self.assertEqual(apply_live_event(cur,paid_event(self.oid),b'raw'),'duplicate')
        self.assertEqual(len(cur.queries),1)
    def test_duplicate_conflicting_body_rejected(self):
        cur=FakeCursor(self.oid,previous_hash='f'*64)
        with self.assertRaises(SettlementRejected): apply_live_event(cur,paid_event(self.oid),b'raw')
    def test_paid_invalid_state_rejected(self):
        cur=FakeCursor(self.oid,state='CREATING')
        with self.assertRaises(SettlementRejected): apply_live_event(cur,paid_event(self.oid),b'raw')
    def test_second_payment_notification_no_duplicate_journal(self):
        cur=FakeCursor(self.oid,state='PAID',prior_pi='pi_123')
        self.assertEqual(apply_live_event(cur,paid_event(self.oid),b'raw'),'applied')
        self.assertFalse(any('INSERT INTO fame_live.payment_journals' in s for s,p in cur.queries))
    def test_refund_delta_journal(self):
        cur=FakeCursor(self.oid,state='PAID',prior_pi='pi_123',refund=200)
        self.assertEqual(apply_live_event(cur,refund_event(cumulative=500),b'raw'),'applied')
        lines=[p for s,p in cur.queries if 'INSERT INTO fame_live.payment_journal_lines' in s]
        self.assertEqual(len(lines),2)
        self.assertEqual(sum(x[3] for x in lines),300)
        self.assertEqual(sum(x[4] for x in lines),300)
    def test_old_refund_does_not_reduce_amount(self):
        cur=FakeCursor(self.oid,state='PARTIALLY_REFUNDED',refund=500)
        self.assertEqual(apply_live_event(cur,refund_event(cumulative=200),b'raw'),'applied')
        self.assertFalse(any('UPDATE fame_live.purchase_intents' in s for s,p in cur.queries))
    def test_over_refund_rejected(self):
        cur=FakeCursor(self.oid,state='PAID')
        with self.assertRaises(SettlementRejected):apply_live_event(cur,refund_event(cumulative=2501),b'raw')
    def test_forged_signature_rejected(self):
        class FakeWebhook:
            @staticmethod
            def construct_event(*args, **kwargs): raise ValueError('bad sig')
        with patch.dict(os.environ, {'FAME_LIVE_WEBHOOK_ENABLED':'1',
                                      'FAME_LIVE_STRIPE_WEBHOOK_SECRET':'whsec_'+'x'*24}),\
             patch.dict(sys.modules, {'stripe':types.SimpleNamespace(Webhook=FakeWebhook)}):
            with self.assertRaises(SettlementRejected): verify_live_signature(b'raw','forged')
    def test_webhook_disabled_before_signature(self):
        with patch.dict(os.environ, {'FAME_LIVE_WEBHOOK_ENABLED':'0'}):
            with self.assertRaises(SettlementRejected):verify_live_signature(b'raw','sig')

if __name__=='__main__':unittest.main()

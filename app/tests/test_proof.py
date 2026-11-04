import sys
import unittest
import uuid
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from fame_stripe_reconcile_test import verify_payment, _outbox_payload, ReconcileRejected, ReconcileRetry

ORDER_ID = str(uuid.UUID('a7e948be-88a0-4d19-a71c-c1f50e6a08c1'))
SID = 'cs_test_1234567890123'
PI = 'pi_1234567890123'
SELLER = 'acct_1234567890123'

def fixture(amount=10000, fee=500):
    s = {'id':SID, 'mode':'payment','livemode':False,'payment_status':'paid',
        'amount_total':amount,'currency':'usd','payment_intent':PI,
        'metadata':{'fame_order_id':ORDER_ID}}
    p = {'id':PI,'livemode':False,'status':'succeeded','amount':amount,
        'amount_received':amount,'currency':'usd','application_fee_amount':fee,
        'transfer_data':{'destination':SELLER},'metadata':{'fame_order_id':ORDER_ID}}
    return s,p

class PaymentProofTests(unittest.TestCase):
    def verify(self,s,p, amount=10000, fee=500):
        return verify_payment(s,p,expected_order_id=ORDER_ID,
            expected_session_id=SID,expected_seller_account=SELLER,
            expected_amount=amount,expected_fee=fee)
    def test_valid(self):
        s,p=fixture();proof=self.verify(s,p)
        self.assertEqual((proof.amount_minor,proof.fee_minor,proof.currency),(10000,500,'USD'))
        payload,digest=_outbox_payload(proof)
        self.assertEqual(payload['order_id'],ORDER_ID)
        self.assertEqual(len(digest),64)
    def test_wrong_mode(self):
        s,p=fixture();p['livemode']=True
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_unpaid(self):
        s,p=fixture();s['payment_status']='unpaid'
        with self.assertRaises(ReconcileRetry):self.verify(s,p)
    def test_wrong_payment_intent(self):
        s,p=fixture();s['payment_intent']='pi_other_valid_123456'
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_wrong_destination(self):
        s,p=fixture();p['transfer_data']['destination']='acct_othervalid123456'
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_wrong_fee(self):
        s,p=fixture();p['application_fee_amount']=300
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_wrong_order(self):
        s,p=fixture();p['metadata']['fame_order_id']=str(uuid.uuid4())
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_wrong_received_amount(self):
        s,p=fixture();p['amount_received']=9999
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_half_up_fee(self):
        s,p=fixture(51,3);proof=self.verify(s,p,amount=51,fee=3)
        self.assertEqual(proof.fee_minor,3)
    def test_wrong_session(self):
        s,p=fixture();s['id']='cs_test_9999999999'
        with self.assertRaises(ReconcileRejected):self.verify(s,p)
    def test_intent_not_succeeded(self):
        s,p=fixture();p['status']='processing'
        with self.assertRaises(ReconcileRetry):self.verify(s,p)

if __name__=='__main__': unittest.main()


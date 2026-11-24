import unittest
from app.live_reconciliation_audit import audit_payment_evidence

ORDER = dict(order_id="order-1", payment_intent_id="pi_live123", seller_account_id="acct_seller123", amount_minor=2000, fee_minor=100, currency="usd", state="PAID", refunded_minor=0)
CHARGE = dict(id="ch_live123", livemode=True, payment_intent="pi_live123", paid=True, captured=True, status="succeeded", amount=2000, currency="usd", application_fee_amount=100, amount_refunded=0, transfer="tr_live123", balance_transaction="txn_live123")
TXN = dict(id="txn_live123", source="ch_live123", amount=2000, fee=88, net=1912, currency="usd")
TRANSFER = dict(id="tr_live123", amount=2000, currency="usd", destination="acct_seller123", livemode=True)

class ReconciliationAuditTests(unittest.TestCase):
    def check(self, order=None, charge=None, txn=TXN, transfer=TRANSFER, **kw):
        return audit_payment_evidence(ORDER if order is None else order, CHARGE if charge is None else charge, txn, transfer, **kw)
    def codes(self, outcome):
        return {x.code for x in outcome.findings}
    def test_matched_evidence_is_not_settlement(self):
        x=self.check(); self.assertEqual(x.status,"EVIDENCE_MATCHED"); self.assertEqual(x.transfer_id,"tr_live123")
    def test_missing_provider_data_requires_review(self):
        x=self.check(txn=None,transfer=None); self.assertEqual(x.status,"REVIEW"); self.assertIn("PROCESSOR_FEE_UNVERIFIED",self.codes(x))
    def test_payment_intent_mismatch_blocks(self):
        x=self.check(charge={**CHARGE,"payment_intent":"pi_other"}); self.assertEqual(x.status,"BLOCKED")
    def test_test_mode_charge_blocks(self):
        self.assertEqual(self.check(charge={**CHARGE,"livemode":False}).status,"BLOCKED")
    def test_wrong_seller_blocks(self):
        self.assertIn("TRANSFER_DESTINATION_MISMATCH",self.codes(self.check(transfer={**TRANSFER,"destination":"acct_other"})))
    def test_destination_transfer_gross_amount(self):
        self.assertIn("TRANSFER_GROSS_MISMATCH",self.codes(self.check(transfer={**TRANSFER,"amount":1900})))
    def test_processing_fee_verification(self):
        self.assertIn("PROCESSOR_FEE_INVALID",self.codes(self.check(txn={**TXN,"net":2000})))
    def test_platform_fee_mismatch(self):
        self.assertIn("APPLICATION_FEE_MISMATCH",self.codes(self.check(charge={**CHARGE,"application_fee_amount":99})))
    def test_refund_provider_mismatch(self):
        o={**ORDER,"state":"PARTIALLY_REFUNDED","refunded_minor":500}
        self.assertIn("REFUND_MISMATCH",self.codes(self.check(order=o)))
    def test_refund_reversal_is_not_proof_of_full_recovery(self):
        o={**ORDER,"state":"PARTIALLY_REFUNDED","refunded_minor":500}
        c={**CHARGE,"amount_refunded":500}
        x=self.check(order=o,charge=c,transfer_reversed_minor=500)
        self.assertEqual(x.status,"REVIEW"); self.assertIn("REFUND_FEE_RECOVERY_UNVERIFIED",self.codes(x))
    def test_unverified_transfer_reversal(self):
        o={**ORDER,"state":"REFUNDED","refunded_minor":2000}
        c={**CHARGE,"amount_refunded":2000}
        self.assertIn("REFUND_TRANSFER_RECOVERY_UNVERIFIED",self.codes(self.check(order=o,charge=c)))
    def test_refund_state_guard(self):
        self.assertIn("ORDER_REFUND_STATE_MISMATCH",self.codes(self.check(order={**ORDER,"state":"REFUNDED"})))
    def test_boolean_amount_rejected(self):
        self.assertEqual(self.check(order={**ORDER,"amount_minor":True}).status,"BLOCKED")
    def test_balance_source_mismatch(self):
        self.assertIn("BALANCE_TRANSACTION_MISMATCH",self.codes(self.check(txn={**TXN,"source":"ch_other"})))
    def test_charge_is_uncaptured(self):
        self.assertIn("CHARGE_NOT_CAPTURED",self.codes(self.check(charge={**CHARGE,"captured":False})))

if __name__ == '__main__': unittest.main()

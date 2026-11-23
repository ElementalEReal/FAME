"""No network or database writes: fail-closed claim transition tests."""
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.live_checkout_claim import (
    _validate_claim_transition,
    claim_live_checkout,
)
from app.live_policy import PurchaseRejected


class CheckoutClaimTests(unittest.TestCase):
    def test_authorized_without_session(self):
        self.assertIsNone(_validate_claim_transition("AUTHORIZED", None))

    def test_creating_requires_reconciliation(self):
        with self.assertRaises(PurchaseRejected) as cm:
            _validate_claim_transition("CREATING", None)
        self.assertIn("RECONCILIATION", str(cm.exception))

    def test_pending_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _validate_claim_transition("PENDING", "cs_live_abc")

    def test_paid_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _validate_claim_transition("PAID", "cs_live_abc")

    def test_authorized_with_session_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _validate_claim_transition("AUTHORIZED", "cs_live_abc")

    def test_disabled_before_database_access(self):
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CLAIM_ENABLED": "0"}):
            with self.assertRaises(PurchaseRejected) as cm:
                claim_live_checkout(order_id=uuid4(),
                                    verified_buyer_profile_id="buyer123")
        self.assertIn("DISABLED", str(cm.exception))

    def test_bad_buyer_before_database_access(self):
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CLAIM_ENABLED": "1"}):
            with self.assertRaises(PurchaseRejected) as cm:
                claim_live_checkout(order_id=uuid4(),
                                    verified_buyer_profile_id="bad buyer")
        self.assertIn("BUYER_INVALID", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

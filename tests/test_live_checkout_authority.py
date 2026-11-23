import os
import unittest
from dataclasses import replace
from unittest.mock import patch
from uuid import uuid4

from app.live_catalog_governance import VerifiedListing
from app.live_checkout_authority import (
    verify_checkout_rows, prepare_live_checkout,
)
from app.live_policy import PurchaseRejected


class CheckoutAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = VerifiedListing(
            "listing123", "seller123", "acct_123ABC",
            "Test Listing", "usd", 2500, "a" * 64,
            True, True,
        )
        s = self.snapshot
        self.catalog = (
            s.listing_id, s.seller_profile_id,
            s.seller_stripe_account_id, s.title,
            s.amount_minor, s.currency,
            s.approval_fingerprint, 2, True,
        )
        self.intent = (
            uuid4(), uuid4(), s.listing_id, "buyer123",
            s.seller_profile_id, s.seller_stripe_account_id,
            s.title, "usd", 2500, 125,
            s.approval_fingerprint, 2, "AUTHORIZED", None,
        )

    def verify(self, snapshot=None, intent=None, catalog=None):
        return verify_checkout_rows(
            self.catalog if catalog is None else catalog,
            self.intent if intent is None else intent,
            self.snapshot if snapshot is None else snapshot,
            "buyer123",
        )

    def test_valid_authorization(self):
        result = self.verify()
        self.assertEqual(result.amount_minor, 2500)
        self.assertEqual(result.fee_minor, 125)

    def test_changed_price_rejected(self):
        with self.assertRaises(PurchaseRejected):
            self.verify(
                snapshot=replace(self.snapshot, amount_minor=3500)
            )

    def test_unapproved_catalog_rejected(self):
        with self.assertRaises(PurchaseRejected):
            self.verify(
                catalog=self.catalog[:-1] + (False,)
            )

    def test_existing_session_rejected(self):
        with self.assertRaises(PurchaseRejected):
            self.verify(
                intent=self.intent[:-1] + ("cs_live_existing",)
            )

    def test_default_disabled_before_database_access(self):
        with patch.dict(os.environ, {
            "FAME_LIVE_CHECKOUT_PREPARE_ENABLED": "0"
        }):
            with self.assertRaises(PurchaseRejected):
                prepare_live_checkout(
                    order_id=uuid4(),
                    verified_buyer_profile_id="buyer123",
                )


if __name__ == "__main__":
    unittest.main()

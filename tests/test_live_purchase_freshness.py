import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.live_catalog_governance import VerifiedListing
from app.live_policy import PurchaseRejected
from app.live_purchase_authority import (
    _require_fresh_catalog,
    create_purchase_intent,
)


class LivePurchaseFreshnessTests(unittest.TestCase):

    def setUp(self):
        self.snapshot = VerifiedListing(
            listing_id="listing123",
            seller_profile_id="seller123",
            seller_stripe_account_id="acct_123ABC",
            title="Original Listing",
            currency="usd",
            amount_minor=2500,
            approval_fingerprint="a" * 64,
            published_public=True,
            seller_eligible=True,
        )
        s = self.snapshot
        self.catalog_row = (
            s.listing_id,
            s.seller_profile_id,
            s.seller_stripe_account_id,
            s.title,
            s.amount_minor,
            s.currency,
            s.approval_fingerprint,
            2,
            True,
        )

    def modified(self, **updates):
        from dataclasses import replace
        return replace(self.snapshot, **updates)

    def test_matching_current_snapshot(self):
        _require_fresh_catalog(
            self.catalog_row,
            self.snapshot,
        )

    def test_changed_price_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _require_fresh_catalog(
                self.catalog_row,
                self.modified(amount_minor=25000),
            )

    def test_changed_fingerprint_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _require_fresh_catalog(
                self.catalog_row,
                self.modified(approval_fingerprint="b" * 64),
            )

    def test_changed_seller_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _require_fresh_catalog(
                self.catalog_row,
                self.modified(seller_profile_id="anotherSeller"),
            )

    def test_changed_stripe_account_rejected(self):
        with self.assertRaises(PurchaseRejected):
            _require_fresh_catalog(
                self.catalog_row,
                self.modified(seller_stripe_account_id="acct_DIFFERENT"),
            )

    def test_missing_trusted_callback_rejected(self):
        with patch.dict(os.environ, {
            "FAME_LIVE_INTENTS_ENABLED": "1",
        }):
            with self.assertRaises(PurchaseRejected):
                create_purchase_intent(
                    intent_id=uuid4(),
                    listing_id="listing123",
                    buyer_profile_id="buyer123",
                )


if __name__ == "__main__":
    unittest.main()

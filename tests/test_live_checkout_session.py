import os
import unittest
from dataclasses import replace
from unittest.mock import patch
from uuid import uuid4

from app.live_checkout_authority import CheckoutAuthorization
from app.live_checkout_claim import CheckoutClaim
from app.live_checkout_session import (
    create_and_bind_live_checkout, verify_stripe_session, bind_live_checkout_session
)
from app.live_policy import PurchaseRejected


class CheckoutSessionTests(unittest.TestCase):
    def setUp(self):
        self.auth = CheckoutAuthorization(
            intent_id=uuid4(), order_id=uuid4(), listing_id="listing123",
            seller_stripe_account_id="acct_ABC123", title="Example",
            amount_minor=2500, fee_minor=125, currency="usd",
            approval_fingerprint="a" * 64, approval_revision=2)
        self.claim = CheckoutClaim(self.auth, "fame-live-checkout-" + str(self.auth.order_id))
        self.session = {
            "id": "cs_live_TEST123", "url": "https://checkout.stripe.com/c/pay/cs_live_TEST123",
            "livemode": True, "mode": "payment", "currency": "usd",
            "amount_total": 2500, "status": "open",
            "metadata": {"fame_order_id": str(self.auth.order_id), "fame_intent_id": str(self.auth.intent_id)},
        }

    def test_valid_session_response(self):
        self.assertEqual(verify_stripe_session(self.session, self.claim)[0], "cs_live_TEST123")

    def test_test_mode_rejected(self):
        with self.assertRaises(PurchaseRejected):
            verify_stripe_session({**self.session, "livemode": False}, self.claim)

    def test_wrong_total_rejected(self):
        with self.assertRaises(PurchaseRejected):
            verify_stripe_session({**self.session, "amount_total": 3500}, self.claim)

    def test_wrong_order_rejected(self):
        with self.assertRaises(PurchaseRejected):
            verify_stripe_session({**self.session, "metadata": {"fame_order_id": "other"}}, self.claim)

    def test_wrong_url_rejected(self):
        with self.assertRaises(PurchaseRejected):
            verify_stripe_session({**self.session, "url": "https://evil.example/"}, self.claim)

    def test_disabled_before_provider_call(self):
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CREATE_ENABLED": "0"}):
            with self.assertRaises(PurchaseRejected):
                create_and_bind_live_checkout(self.claim, create_session=lambda _: self.fail("Provider invoked"))

    def test_wrong_idempotency_key_rejected(self):
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CREATE_ENABLED": "1"}):
            with self.assertRaises(PurchaseRejected):
                create_and_bind_live_checkout(replace(self.claim, stripe_idempotency_key="other"), create_session=lambda _: self.fail("Provider invoked"))

    def test_duplicate_dispatch_does_not_call_provider(self):
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CREATE_ENABLED": "1"}), \
             patch("app.live_checkout_session.reserve_live_dispatch", side_effect=PurchaseRejected("LIVE_CHECKOUT_DISPATCH_ALREADY_ATTEMPTED")):
            with self.assertRaisesRegex(PurchaseRejected, "ALREADY_ATTEMPTED"):
                create_and_bind_live_checkout(self.claim, create_session=lambda _: self.fail("Provider invoked"))

    def test_ambiguous_provider_failure(self):
        def failed(_):
            raise ConnectionError("network")
        with patch.dict(os.environ, {"FAME_LIVE_CHECKOUT_CREATE_ENABLED": "1"}), \
             patch("app.live_checkout_session.reserve_live_dispatch"):
            with self.assertRaisesRegex(PurchaseRejected, "OUTCOME_UNCERTAIN"):
                create_and_bind_live_checkout(self.claim, create_session=failed)


if __name__ == "__main__":
    unittest.main()

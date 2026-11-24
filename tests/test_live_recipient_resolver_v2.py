"""FAME recipient-only Connect resolution acceptance (no Stripe/network/DB)."""
import unittest
from unittest.mock import patch

from app.live_policy import PurchaseRejected
from app.live_seller_resolver import resolve_live_seller, _stripe_get

SELLER = "participant-alpha"
ACCOUNT = "acct_1ValidSeller123"


def snapshot(*, config="recipient", status="active", metadata=True, livemode=True):
    return {
        "id": ACCOUNT, "livemode": livemode,
        "metadata": {"fame_seller_key": SELLER} if metadata else {},
        "applied_configurations": [config],
        "configuration": {"recipient": {"capabilities": {
            "stripe_balance": {"stripe_transfers": {"status": status}}
        }}} if config == "recipient" else None,
    }


def resolve(payload, row=(ACCOUNT, "verified-timestamp")):
    return resolve_live_seller(SELLER, lookup=lambda _: row,
                               stripe_get=lambda _: payload)


class LiveRecipientResolverTests(unittest.TestCase):
    def test_recipient_only_active_transfers_allowed(self):
        self.assertEqual(resolve(snapshot()), (ACCOUNT, True))

    def test_pending_transfers_not_ready(self):
        self.assertEqual(resolve(snapshot(status="pending")), (ACCOUNT, False))

    def test_customer_only_record_not_ready(self):
        self.assertEqual(resolve(snapshot(config="customer")), (ACCOUNT, False))

    def test_unverified_database_mapping_fails(self):
        with self.assertRaises(PurchaseRejected):
            resolve(snapshot(), row=(ACCOUNT, None))

    def test_metadata_mismatch_fails(self):
        with self.assertRaises(PurchaseRejected):
            resolve(snapshot(metadata=False))

    def test_testmode_account_fails(self):
        with self.assertRaises(PurchaseRejected):
            resolve(snapshot(livemode=False))

    def test_null_included_recipient_refuses_ready(self):
        data = snapshot(); data["configuration"] = None
        with self.assertRaises(PurchaseRejected):
            resolve(data)

    def test_unexpected_payload_refuses_ready(self):
        with self.assertRaises(PurchaseRejected):
            resolve({"id": ACCOUNT, "livemode": True, "metadata": {"fame_seller_key": SELLER},
                     "applied_configurations": ["recipient"], "configuration": {"recipient": {}}})

    def test_transport_requires_verify_switch(self):
        with patch.dict("os.environ", {"FAME_LIVE_STRIPE_SECRET_KEY": "sk_live_dummy", "FAME_LIVE_STRIPE_VERIFY_ENABLED": "0"}):
            with self.assertRaises(PurchaseRejected):
                _stripe_get(ACCOUNT)


if __name__ == "__main__":
    unittest.main()

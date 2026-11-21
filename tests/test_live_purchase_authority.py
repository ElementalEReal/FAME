"""Offline gate tests. Run from finance-ledger root after copying the module."""
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from app.live_policy import PurchaseRejected
from app.live_purchase_authority import create_purchase_intent, require_uuid4


class PurchaseAuthorityGateTests(unittest.TestCase):
    def test_accepts_v4_uuid(self):
        value = uuid4()
        self.assertEqual(value, require_uuid4(str(value)))

    def test_rejects_bad_uuid(self):
        with self.assertRaises(PurchaseRejected):
            require_uuid4('not-a-uuid')

    def test_disabled_by_default(self):
        with patch.dict(os.environ, {'FAME_LIVE_INTENTS_ENABLED': '0'}):
            with self.assertRaisesRegex(PurchaseRejected, 'LIVE_INTENTS_DISABLED'):
                create_purchase_intent(intent_id=uuid4(), listing_id='item1', buyer_profile_id='buyer1')

    def test_no_environment_cannot_write(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(PurchaseRejected, 'LIVE_INTENTS_DISABLED'):
                create_purchase_intent(intent_id=uuid4(), listing_id='item1', buyer_profile_id='buyer1')


if __name__ == '__main__':
    unittest.main()

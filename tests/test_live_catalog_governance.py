import os
import unittest
from unittest.mock import patch
from uuid import uuid4
from app.live_policy import PurchaseRejected
from app.live_catalog_governance import VerifiedListing, _valid, register_disabled_listing, decide_live_listing

class CatalogGovernanceGates(unittest.TestCase):
    def test_disabled_default_no_callback(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(PurchaseRejected, 'LIVE_CATALOG_WRITES_DISABLED'):
                register_disabled_listing(listing_id='l', fetch_verified_listing=lambda _: self.fail('called'))
    def test_disabled_approval_no_callback(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(PurchaseRejected, 'LIVE_CATALOG_WRITES_DISABLED'):
                decide_live_listing(listing_id='l',request_id=uuid4(),action='APPROVE',reason='',require_verified_reviewer=lambda: self.fail('called'),fetch_verified_listing=lambda _: self.fail('called'))
    def test_valid_listing(self):
        row=VerifiedListing('listing','seller','acct_ABC12','A thing','usd',100,'a'*64,True,True)
        _valid(row,'listing')
    def test_reject_unready_seller(self):
        row=VerifiedListing('listing','seller','acct_ABC12','A thing','usd',100,'a'*64,True,False)
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_LISTING_NOT_ELIGIBLE'):
            _valid(row,'listing')
    def test_reject_wrong_price_type(self):
        row=VerifiedListing('listing','seller','acct_ABC12','A thing','usd',True,'a'*64,True,True)
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_AMOUNT_INVALID'):
            _valid(row,'listing')
    def test_reject_wrong_listing(self):
        row=VerifiedListing('listing','seller','acct_ABC12','A thing','usd',100,'a'*64,True,True)
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_LISTING_MISMATCH'):
            _valid(row,'other')

if __name__ == '__main__': unittest.main()

import unittest
from datetime import datetime, timezone
from app.live_policy import PurchaseRejected
from app.live_seller_resolver import resolve_live_seller

ACCOUNT = 'acct_LiveCandidate123'
SELLER = 'seller_A'
WHEN = datetime.now(timezone.utc)

def acct(*, live=True, seller=SELLER, card='active', transfers='active', payouts='active', aid=ACCOUNT):
    return {'id':aid,'livemode':live,'metadata':{'fame_seller_key':seller},
            'configuration':{'merchant':{'capabilities':{
                'card_payments':{'status':card},'stripe_balance':{'payouts':{'status':payouts}}}},
                'recipient':{'capabilities':{'stripe_balance':{'stripe_transfers':{'status':transfers}}}}}}

class LiveSellerResolverTests(unittest.TestCase):
    def resolve(self, row=(ACCOUNT, WHEN), provider=None, seller=SELLER):
        return resolve_live_seller(seller, lookup=lambda s:row, stripe_get=lambda a:acct() if provider is None else provider)
    def test_ready(self):
        self.assertEqual(self.resolve(), (ACCOUNT, True))
    def test_unready(self):
        self.assertEqual(self.resolve(provider=acct(transfers='pending')),(ACCOUNT,False))
    def test_test_account_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_STRIPE_ACCOUNT_MISMATCH'):
            self.resolve(provider=acct(live=False))
    def test_wrong_account_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_STRIPE_ACCOUNT_MISMATCH'):
            self.resolve(provider=acct(aid='acct_Other'))
    def test_wrong_owner_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_SELLER_OWNERSHIP_MISMATCH'):
            self.resolve(provider=acct(seller='someone_else'))
    def test_unverified_mapping_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_SELLER_NOT_VERIFIED'):
            self.resolve(row=(ACCOUNT,None))
    def test_missing_mapping_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_SELLER_NOT_VERIFIED'):
            self.resolve(row=None)
    def test_bad_seller_denied(self):
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_SELLER_ID_INVALID'):
            self.resolve(seller='bad seller')
    def test_provider_failure_denied(self):
        def failure(_):raise OSError('offline')
        with self.assertRaisesRegex(PurchaseRejected,'LIVE_STRIPE_VERIFICATION_UNAVAILABLE'):
            resolve_live_seller(SELLER,lookup=lambda s:(ACCOUNT,WHEN),stripe_get=failure)

if __name__ == '__main__': unittest.main()

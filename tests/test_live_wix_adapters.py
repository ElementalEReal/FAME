import hashlib
import hmac
import json
import os
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from app.live_policy import PurchaseRejected
from app.live_wix_adapters import verify_wix_reviewer_proof,fetch_wix_snapshot

SECRET = 'test-only-wix-review-proof-' + 'x'*40
SNAP = 'test-only-snapshot-secret-' + 'z'*40
URL = 'https://example.wixsite.com/site/_functions/fameLiveSnapshot'
FP='a'*64

class TrustBridgeTests(unittest.TestCase):
    def request(self,member='reviewer-good',raw=b'{"action":"APPROVE"}',signature_correct=True):
        ts=str(int(time.time()));nonce='a'*48;path='/v1/live/catalog/decision'
        digest=hashlib.sha256(raw).hexdigest()
        msg='\n'.join(['POST',path,ts,nonce,digest,member])
        sig=hmac.new(SECRET.encode(),msg.encode(),hashlib.sha256).hexdigest()
        if not signature_correct:sig='0'*64
        headers={'x-fame-live-member':member,'x-fame-member-proof':sig,'x-fame-timestamp':ts,'x-fame-nonce':nonce}
        return SimpleNamespace(headers=headers,method='POST',url=SimpleNamespace(path=path),state=SimpleNamespace(live_signed_raw_body=raw))
    def test_valid_member_proof(self):
        with patch.dict(os.environ,{'FAME_LIVE_REVIEW_PROOF_SECRET':SECRET}):
            self.assertEqual(verify_wix_reviewer_proof(self.request()),'reviewer-good')
    def test_reject_forged_member(self):
        with patch.dict(os.environ,{'FAME_LIVE_REVIEW_PROOF_SECRET':SECRET}):
            with self.assertRaisesRegex(PurchaseRejected,'LIVE_WIX_MEMBER_PROOF_INVALID'):
                verify_wix_reviewer_proof(self.request(signature_correct=False))
    def test_reject_body_mutation(self):
        r=self.request();r.state.live_signed_raw_body=b'changed'
        with patch.dict(os.environ,{'FAME_LIVE_REVIEW_PROOF_SECRET':SECRET}):
            with self.assertRaises(PurchaseRejected):verify_wix_reviewer_proof(r)
    def test_no_cached_body_fails_closed(self):
        r=self.request();del r.state.live_signed_raw_body
        with patch.dict(os.environ,{'FAME_LIVE_REVIEW_PROOF_SECRET':SECRET}):
            with self.assertRaisesRegex(PurchaseRejected,'LIVE_SIGNED_BODY_UNAVAILABLE'):
                verify_wix_reviewer_proof(r)
    def test_render_not_trusting_wix_stripe_account(self):
        snapshot={'ok':True,'listing_id':'list1','seller_profile_id':'seller1','title':'Item','currency':'usd','amount_minor':1000,'approval_fingerprint':FP,'published_public':True,'seller_stripe_account_id':'acct_forged'}
        with patch.dict(os.environ,{'FAME_LIVE_SNAPSHOT_SECRET':SNAP,'FAME_LIVE_WIX_SNAPSHOT_URL':URL}):
            result=fetch_wix_snapshot('list1',account_resolver=lambda x: ('acct_realready',True),transport=lambda *args:snapshot)
        self.assertEqual(result.seller_stripe_account_id,'acct_realready')
    def test_reject_unpublished(self):
        snapshot={'ok':True,'listing_id':'list1','seller_profile_id':'seller1','title':'Item','currency':'usd','amount_minor':1000,'approval_fingerprint':FP,'published_public':False}
        with patch.dict(os.environ,{'FAME_LIVE_SNAPSHOT_SECRET':SNAP,'FAME_LIVE_WIX_SNAPSHOT_URL':URL}):
            with self.assertRaisesRegex(PurchaseRejected,'LIVE_WIX_NOT_PURCHASABLE'):
                fetch_wix_snapshot('list1',account_resolver=lambda x: ('acct_ready',True),transport=lambda *args:snapshot)
    def test_missing_secret_fail_closed(self):
        with patch.dict(os.environ,{'FAME_LIVE_SNAPSHOT_SECRET':'','FAME_LIVE_WIX_SNAPSHOT_URL':URL}):
            with self.assertRaisesRegex(PurchaseRejected,'LIVE_WIX_TRUST_NOT_CONFIGURED'):
                fetch_wix_snapshot('list1',account_resolver=lambda x: ('acct_ready',True),transport=lambda *args:{})

if __name__=='__main__':unittest.main()

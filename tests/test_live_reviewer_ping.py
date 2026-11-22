import hashlib
import hmac
import json
import os
import unittest
from unittest.mock import patch
from app.live_reviewer_ping import verify, ROUTE

class ReviewerPingTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'FAME_LIVE_BRIDGE_SECRET':'b'*64,
            'FAME_LIVE_REVIEW_PROOF_SECRET':'p'*64,
            'FAME_LIVE_REVIEWER_MEMBER_IDS':'reviewer-1'}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.raw = json.dumps({'purpose':'READ_ONLY_REVIEWER_PROOF','reviewer_member_id':'reviewer-1'},separators=(',',':')).encode()
        ts='1795222800'; nonce='a'*48
        msg='\n'.join(['POST',ROUTE,ts,nonce,hashlib.sha256(self.raw).hexdigest()])
        self.headers={'x-fame-timestamp':ts,'x-fame-nonce':nonce,
            'x-fame-live-member':'reviewer-1',
            'x-fame-signature':hmac.new(b'b'*64,msg.encode(),hashlib.sha256).hexdigest(),
            'x-fame-member-proof':hmac.new(b'p'*64,(msg+'\nreviewer-1').encode(),hashlib.sha256).hexdigest()}
    def check(self, raw=None, headers=None, method='POST', path=ROUTE):
        return verify(self.raw if raw is None else raw, self.headers if headers is None else headers, method, path, now=1795222800)
    def test_valid(self): self.assertTrue(self.check())
    def test_modified_body(self): self.assertFalse(self.check(raw=self.raw+b' '))
    def test_invalid_signature(self): self.assertFalse(self.check(headers={**self.headers,'x-fame-signature':'0'*64}))
    def test_invalid_proof(self): self.assertFalse(self.check(headers={**self.headers,'x-fame-member-proof':'0'*64}))
    def test_member_mismatch(self): self.assertFalse(self.check(headers={**self.headers,'x-fame-live-member':'reviewer-2'}))
    def test_wrong_path(self): self.assertFalse(self.check(path='/v1/live/catalog/decision'))
    def test_expired(self): self.assertFalse(verify(self.raw,self.headers,'POST',ROUTE,now=1795223401))
    def test_not_allowlisted(self):
        with patch.dict(os.environ,{'FAME_LIVE_REVIEWER_MEMBER_IDS':''}): self.assertFalse(self.check())
    def test_missing_secret(self):
        with patch.dict(os.environ,{'FAME_LIVE_BRIDGE_SECRET':''}): self.assertFalse(self.check())
    def test_bad_purpose(self): self.assertFalse(self.check(raw=self.raw.replace(b'READ_ONLY_REVIEWER_PROOF',b'APPROVE')))

if __name__ == '__main__': unittest.main()

"""These tests intentionally do not mount routes or connect to Neon."""
import unittest
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch
from fastapi import HTTPException
from app.live_governance_routes import (
    LiveDecision, decide_listing, verified_reviewer_for_request
)
from app.live_policy import PurchaseRejected

class ReviewerBindingTests(unittest.TestCase):
    def setUp(self):
        self.request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
        self.body=LiveDecision(listing_id='listing-demo',request_id=uuid4(),
            reviewer_member_id='approved-reviewer',action='APPROVE',reason='Review')

    def test_missing_adapters_still_fail_closed(self):
        with self.assertRaises(HTTPException) as e:
            decide_listing(self.body,self.request)
        self.assertEqual(e.exception.status_code,503)

    def test_forged_claim_rejected_before_allowlist(self):
        with patch('app.live_governance_routes.require_live_reviewer',side_effect=AssertionError('allowlist reached')):
            with self.assertRaises(HTTPException) as e:
                verified_reviewer_for_request(lambda request:'other-member',self.request,'approved-reviewer')
        self.assertEqual(e.exception.status_code,403)

    def test_missing_verification_rejected(self):
        with self.assertRaises(HTTPException) as e:
            verified_reviewer_for_request(None,self.request,'approved-reviewer')
        self.assertEqual(e.exception.status_code,503)

    def test_verified_member_still_needs_live_allowlist(self):
        with patch('app.live_governance_routes.require_live_reviewer',side_effect=PurchaseRejected('LIVE_REVIEWER_FORBIDDEN')):
            with self.assertRaisesRegex(PurchaseRejected,'LIVE_REVIEWER_FORBIDDEN'):
                verified_reviewer_for_request(lambda request:'approved-reviewer',self.request,'approved-reviewer')

    def test_verified_and_allowlisted_member_accepted(self):
        with patch('app.live_governance_routes.require_live_reviewer',return_value='approved-reviewer') as allow:
            result=verified_reviewer_for_request(lambda request:'approved-reviewer',self.request,'approved-reviewer')
        self.assertEqual(result,'approved-reviewer')
        allow.assert_called_once_with('approved-reviewer')

if __name__=='__main__': unittest.main()

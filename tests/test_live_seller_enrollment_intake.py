import hashlib
import hmac
import json
import unittest
from app.live_seller_enrollment_intake import PATH, checked_claim, verify_signed_request

SECRET = 'a' * 40
NOW = 1700000000
NONCE = 'c' * 48
BODY = b'{"seller_profile_id":"abc-123","stripe_account_id":"acct_ABC123"}'

def headers(body=BODY, timestamp=str(NOW), nonce=NONCE):
    digest = hashlib.sha256(body).hexdigest()
    message = '\n'.join(['POST', PATH, timestamp, nonce, digest]).encode()
    signature = hmac.new(SECRET.encode(), message, hashlib.sha256).hexdigest()
    return {'x-fame-timestamp': timestamp, 'x-fame-nonce': nonce, 'x-fame-signature': signature}

class SellerEnrollmentIntakeTests(unittest.TestCase):
    def test_valid_signed_request(self):
        self.assertEqual(verify_signed_request(BODY, headers(), SECRET, now=NOW), NONCE)
    def test_valid_claim(self):
        self.assertEqual(checked_claim(BODY), ('abc-123','acct_ABC123'))
    def test_changed_body_denied(self):
        with self.assertRaises(ValueError):
            verify_signed_request(BODY + b' ', headers(), SECRET, now=NOW)
    def test_wrong_secret_denied(self):
        with self.assertRaises(ValueError):
            verify_signed_request(BODY, headers(), 'z'*40, now=NOW)
    def test_stale_timestamp_denied(self):
        with self.assertRaises(ValueError):
            verify_signed_request(BODY, headers(), SECRET, now=NOW + 301)
    def test_future_timestamp_denied(self):
        with self.assertRaises(ValueError):
            verify_signed_request(BODY, headers(), SECRET, now=NOW - 301)
    def test_invalid_nonce_denied(self):
        with self.assertRaises(ValueError):
            verify_signed_request(BODY, headers(nonce='bad'), SECRET, now=NOW)
    def test_client_seller_identity_missing_denied(self):
        with self.assertRaises(ValueError):
            checked_claim(b'{"stripe_account_id":"acct_ABC123"}')
    def test_extra_fields_denied(self):
        with self.assertRaises(ValueError):
            checked_claim(BODY[:-1] + b',"approved":true}')
    def test_invalid_account_denied(self):
        with self.assertRaises(ValueError):
            checked_claim(b'{"seller_profile_id":"abc-123","stripe_account_id":"not_an_account"}')
    def test_bad_json_denied(self):
        with self.assertRaises(ValueError):
            checked_claim(b'{')
    def test_body_limit(self):
        with self.assertRaises(ValueError):
            verify_signed_request(b'x'*2049, headers(), SECRET, now=NOW)

if __name__ == '__main__': unittest.main()

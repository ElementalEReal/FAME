import os
import unittest
from uuid import uuid4
from unittest.mock import patch

from app.live_catalog_governance import decide_live_listing
from app.live_policy import PurchaseRejected


class LiveApprovalIsolationTests(unittest.TestCase):

    def test_approval_requires_independent_switch(self):
        def forbidden_callback(*args, **kwargs):
            self.fail("SECURITY_FAILURE_CALLBACK_EXECUTED")

        with patch.dict(os.environ, {
            "FAME_LIVE_CATALOG_WRITES_ENABLED": "1",
            "FAME_LIVE_APPROVAL_WRITES_ENABLED": "0"
        }):
            with self.assertRaisesRegex(
                PurchaseRejected,
                "^LIVE_APPROVAL_WRITES_DISABLED$"
            ):
                decide_live_listing(
                    listing_id="fame-security-test",
                    request_id=uuid4(),
                    action="APPROVE",
                    reason="Security regression test",
                    require_verified_reviewer=forbidden_callback,
                    fetch_verified_listing=forbidden_callback
                )


if __name__ == "__main__":
    unittest.main()

import unittest
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException

from app.live_governance_routes import (
    LiveDecision,
    decide_listing,
)


class LiveGovernanceRouteTests(unittest.TestCase):

    def test_missing_trusted_adapters_fails_closed(self):
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace())
        )

        body = LiveDecision(
            listing_id="fame-security-test",
            reviewer_member_id="test-reviewer",
            request_id=uuid4(),
            action="APPROVE",
            reason="Integration safety check",
        )

        with self.assertRaises(HTTPException) as result:
            decide_listing(body, request)

        self.assertEqual(result.exception.status_code, 503)
        self.assertEqual(
            result.exception.detail,
            "LIVE_GOVERNANCE_ADAPTERS_NOT_CONFIGURED",
        )


if __name__ == "__main__":
    unittest.main()

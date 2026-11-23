import os
import subprocess
import sys
import unittest


class LiveGovernanceWiringTests(unittest.TestCase):

    def inspect(self, bridge_enabled):
        script = """
from app.live_main import app
path = '/v1/live/catalog/decision'
mounted = (
    'post' in app.openapi()
        .get('paths', {})
        .get(path, {})
)
print('MOUNTED=' + str(mounted))
print('REVIEWER=' + str(callable(
    getattr(app.state, 'live_reviewer_adapter', None)
)))
print('LISTING=' + str(callable(
    getattr(app.state, 'live_listing_adapter', None)
)))
"""
        env = os.environ.copy()
        env["FAME_LIVE_BRIDGE_ENABLED"] = bridge_enabled

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
        )

        self.assertEqual(
            result.returncode, 0,
            result.stderr,
        )
        return result.stdout

    def test_disabled_bridge_has_no_governance_route(self):
        result = self.inspect("0")
        self.assertIn("MOUNTED=False", result)

    def test_enabled_bridge_installs_trusted_adapters(self):
        result = self.inspect("1")
        self.assertIn("MOUNTED=True", result)
        self.assertIn("REVIEWER=True", result)
        self.assertIn("LISTING=True", result)


if __name__ == "__main__":
    unittest.main()

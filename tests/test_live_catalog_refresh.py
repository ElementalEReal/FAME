import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from app.live_catalog_governance import (
    VerifiedListing,
    refresh_disabled_listing,
)
from app.live_policy import PurchaseRejected


class FakeCursor:
    def __init__(self, row, update_count=1):
        self.row = row
        self.rowcount = update_count
        self.queries = []

    def execute(self, sql, params=None):
        self.queries.append((sql, params))

    def fetchone(self):
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def cursor(self):
        return self.fake_cursor


class CatalogRefreshTests(unittest.TestCase):

    def setUp(self):
        self.snapshot = VerifiedListing(
            listing_id="listing123",
            seller_profile_id="seller123",
            seller_stripe_account_id="acct_123ABC",
            title="Updated Listing",
            currency="usd",
            amount_minor=2500,
            approval_fingerprint="b" * 64,
            published_public=True,
            seller_eligible=True,
        )

    def row(self, enabled=False, changed=True):
        s = self.snapshot
        return (
            s.listing_id,
            s.seller_profile_id,
            s.seller_stripe_account_id,
            "Original Listing" if changed else s.title,
            s.currency,
            2000 if changed else s.amount_minor,
            "a" * 64 if changed else s.approval_fingerprint,
            3,
            enabled,
        )

    def run_refresh(self, row, update_count=1):
        cursor = FakeCursor(row, update_count)

        @contextmanager
        def database(read_only=True):
            self.assertFalse(read_only)
            yield FakeConnection(cursor)

        with patch.dict(os.environ, {
            "FAME_LIVE_CATALOG_WRITES_ENABLED": "1",
        }), patch(
            "app.live_catalog_governance.live_database",
            database,
        ):
            result = refresh_disabled_listing(
                listing_id="listing123",
                fetch_verified_listing=lambda _: self.snapshot,
            )

        return result, cursor

    def test_writes_disabled(self):
        with patch.dict(os.environ, {
            "FAME_LIVE_CATALOG_WRITES_ENABLED": "0",
        }):
            with self.assertRaises(PurchaseRejected):
                refresh_disabled_listing(
                    listing_id="listing123",
                    fetch_verified_listing=lambda _: self.fail(
                        "Snapshot callback should not run"
                    ),
                )

    def test_approved_listing_rejected(self):
        with self.assertRaises(PurchaseRejected):
            self.run_refresh(self.row(enabled=True))

    def test_unchanged_listing_keeps_revision(self):
        revision, cursor = self.run_refresh(
            self.row(changed=False)
        )
        self.assertEqual(revision, 3)
        self.assertEqual(len(cursor.queries), 1)

    def test_changed_listing_remains_disabled(self):
        revision, cursor = self.run_refresh(self.row())
        self.assertEqual(revision, 4)
        self.assertEqual(len(cursor.queries), 2)

        sql, params = cursor.queries[-1]
        self.assertIn("enabled=FALSE", sql)
        self.assertEqual(params[-2:], ("listing123", 3))
        self.assertEqual(params[5], "b" * 64)

    def test_concurrent_update_conflict(self):
        with self.assertRaises(PurchaseRejected):
            self.run_refresh(self.row(), update_count=0)


if __name__ == "__main__":
    unittest.main()

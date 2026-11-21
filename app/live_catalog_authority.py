"""FAME LIVE catalog authority — read-only foundation.

LIVE approvals and revocations must use a separate
authenticated, transactional approval service.
"""

from app.live_db import live_database
from app.live_policy import Catalog, PurchaseRejected, ID


def get_live_catalog_listing(listing_id: str) -> Catalog:
    """Read the authoritative LIVE listing from Neon."""

    if not isinstance(listing_id, str) or not ID.fullmatch(listing_id):
        raise PurchaseRejected("LIVE_LISTING_ID_INVALID")

    with live_database(read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    listing_id,
                    seller_profile_id,
                    seller_stripe_account_id,
                    title,
                    amount_minor,
                    currency,
                    approval_fingerprint,
                    approval_revision,
                    enabled
                FROM fame_live.catalog
                WHERE listing_id = %s
            """, (listing_id,))

            row = cur.fetchone()

            if row is None:
                raise PurchaseRejected("LIVE_LISTING_NOT_FOUND")

            return Catalog(*row)

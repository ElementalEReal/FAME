"""FAME LIVE Checkout preparation authority.

Read-only business operation with PostgreSQL row locks.
Does NOT create Stripe Sessions, charge cards, or update orders.
Disabled by default.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID

from app.live_catalog_governance import VerifiedListing, _valid
from app.live_db import live_database
from app.live_policy import (
    Catalog, Intent, PurchaseRejected, authorize, ID,
)
from app.live_purchase_authority import require_uuid4
from app.live_seller_resolver import resolve_live_seller
from app.live_wix_adapters import fetch_wix_snapshot


@dataclass(frozen=True)
class CheckoutAuthorization:
    intent_id: UUID
    order_id: UUID
    listing_id: str
    seller_stripe_account_id: str
    title: str
    amount_minor: int
    fee_minor: int
    currency: str
    approval_fingerprint: str
    approval_revision: int


def verify_checkout_rows(
    catalog_row, intent_row, snapshot, buyer_profile_id
):
    """Authorize only exact, current, immutable financial records."""
    if not isinstance(buyer_profile_id, str) or not ID.fullmatch(
        buyer_profile_id
    ):
        raise PurchaseRejected("LIVE_BUYER_INVALID")

    if type(snapshot) is not VerifiedListing:
        raise PurchaseRejected("LIVE_TRUSTED_SNAPSHOT_REQUIRED")

    catalog = Catalog(*catalog_row)
    _valid(snapshot, catalog.listing_id)

    if not catalog.enabled:
        raise PurchaseRejected("LIVE_LISTING_NOT_APPROVED")

    current = (
        snapshot.listing_id,
        snapshot.seller_profile_id,
        snapshot.seller_stripe_account_id,
        snapshot.title.strip(),
        snapshot.currency,
        snapshot.amount_minor,
        snapshot.approval_fingerprint,
    )

    stored = (
        catalog.listing_id,
        catalog.seller_profile_id,
        catalog.seller_stripe_account_id,
        catalog.title,
        catalog.currency,
        catalog.amount_minor,
        catalog.approval_fingerprint,
    )

    if current != stored:
        raise PurchaseRejected("LIVE_CHECKOUT_SOURCE_STALE")

    (
        intent_id, order_id, listing_id, buyer_id, seller_id,
        account_id, title, currency, amount, fee,
        fingerprint, revision, state, session_id
    ) = intent_row

    if state != "AUTHORIZED" or session_id is not None:
        raise PurchaseRejected("LIVE_CHECKOUT_ORDER_NOT_READY")

    if buyer_id != buyer_profile_id:
        raise PurchaseRejected("LIVE_CHECKOUT_BUYER_MISMATCH")

    intent = Intent(
        require_uuid4(intent_id),
        listing_id,
        buyer_id,
        seller_id,
        amount,
        revision,
        fingerprint,
    )
    decision = authorize(catalog, intent)

    if (
        account_id != decision["seller_stripe_account_id"]
        or title != decision["title"]
        or currency != decision["currency"]
        or fee != decision["fee_minor"]
    ):
        raise PurchaseRejected("LIVE_CHECKOUT_ORDER_MISMATCH")

    return CheckoutAuthorization(
        intent_id=require_uuid4(intent_id),
        order_id=require_uuid4(order_id),
        listing_id=listing_id,
        seller_stripe_account_id=account_id,
        title=title,
        amount_minor=amount,
        fee_minor=fee,
        currency=currency,
        approval_fingerprint=fingerprint,
        approval_revision=revision,
    )


def prepare_live_checkout(
    *,
    order_id: str | UUID,
    verified_buyer_profile_id: str,
) -> CheckoutAuthorization:
    """Server-only preparation. Never expose as unauthenticated route.

    Caller must establish buyer identity independently.
    No arbitrary snapshot, price, fee, or seller is accepted.
    """
    if os.getenv("FAME_LIVE_CHECKOUT_PREPARE_ENABLED") != "1":
        raise PurchaseRejected("LIVE_CHECKOUT_PREPARE_DISABLED")

    uid = require_uuid4(order_id)

    if (
        not isinstance(verified_buyer_profile_id, str)
        or not ID.fullmatch(verified_buyer_profile_id)
    ):
        raise PurchaseRejected("LIVE_BUYER_INVALID")

    # Obtain listing identity from the persisted order.
    with live_database(read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT listing_id
                FROM fame_live.purchase_intents
                WHERE order_id = %s
            """, (uid,))
            result = cur.fetchone()

    if result is None:
        raise PurchaseRejected("LIVE_ORDER_NOT_FOUND")

    listing_id = result[0]

    # Independently check current Wix publication and LIVE Stripe seller.
    snapshot = fetch_wix_snapshot(
        listing_id,
        account_resolver=resolve_live_seller,
    )
    _valid(snapshot, listing_id)

    # Lock catalog first, then intent, matching existing write ordering.
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT listing_id,seller_profile_id,
                       seller_stripe_account_id,title,amount_minor,
                       currency,approval_fingerprint,
                       approval_revision,enabled
                FROM fame_live.catalog
                WHERE listing_id=%s FOR UPDATE
            """, (listing_id,))
            catalog_row = cur.fetchone()

            if catalog_row is None:
                raise PurchaseRejected("LIVE_CATALOG_NOT_FOUND")

            cur.execute("""
                SELECT intent_id,order_id,listing_id,
                       buyer_profile_id,seller_profile_id,
                       seller_stripe_account_id,title,currency,
                       amount_minor,fee_minor,approval_fingerprint,
                       approval_revision,state,stripe_session_id
                FROM fame_live.purchase_intents
                WHERE order_id=%s FOR UPDATE
            """, (uid,))
            intent_row = cur.fetchone()

            if intent_row is None:
                raise PurchaseRejected("LIVE_ORDER_NOT_FOUND")

            return verify_checkout_rows(
                catalog_row,
                intent_row,
                snapshot,
                verified_buyer_profile_id,
            )

"""FAME LIVE: reserve an already-authorized purchase for Checkout creation.

No Stripe calls or HTTP routes. A CREATING order is deliberately NOT retried
by this module: uncertain Stripe outcomes need a separate reconciliation path.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID

from app.live_checkout_authority import CheckoutAuthorization, verify_checkout_rows
from app.live_db import live_database
from app.live_policy import ID, PurchaseRejected
from app.live_purchase_authority import require_uuid4
from app.live_seller_resolver import resolve_live_seller
from app.live_wix_adapters import fetch_wix_snapshot


@dataclass(frozen=True)
class CheckoutClaim:
    authorization: CheckoutAuthorization
    stripe_idempotency_key: str


def _validate_claim_transition(state, stripe_session_id):
    """Only an unbound, freshly AUTHORIZED order may be claimed."""
    if state == "CREATING":
        raise PurchaseRejected("LIVE_CHECKOUT_RECONCILIATION_REQUIRED")
    if state != "AUTHORIZED" or stripe_session_id is not None:
        raise PurchaseRejected("LIVE_CHECKOUT_ORDER_NOT_CLAIMABLE")


def claim_live_checkout(*, order_id: str | UUID,
                        verified_buyer_profile_id: str) -> CheckoutClaim:
    """Transition AUTHORIZED -> CREATING in one transaction after re-verification.

    `verified_buyer_profile_id` must come from trusted server-side authentication.
    No HTTP route calls this function yet. No Stripe Session is created here.
    Only approved code, not browser input, supplies Wix/Stripe verification.
    """
    if os.getenv("FAME_LIVE_CHECKOUT_CLAIM_ENABLED") != "1":
        raise PurchaseRejected("LIVE_CHECKOUT_CLAIM_DISABLED")
    uid = require_uuid4(order_id)
    if not isinstance(verified_buyer_profile_id, str) or not ID.fullmatch(
        verified_buyer_profile_id
    ):
        raise PurchaseRejected("LIVE_BUYER_INVALID")

    # Fetch only listing ID before contacting the trusted external authorities.
    with live_database(read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT listing_id FROM fame_live.purchase_intents
                WHERE order_id = %s
            """, (uid,))
            identity = cur.fetchone()
    if identity is None:
        raise PurchaseRejected("LIVE_ORDER_NOT_FOUND")

    listing_id = identity[0]
    snapshot = fetch_wix_snapshot(
        listing_id, account_resolver=resolve_live_seller
    )

    # Catalog-first ordering is consistent with approval and purchase intent.
    # PostgreSQL row locks serialize competing claims and revocations.
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT listing_id,seller_profile_id,seller_stripe_account_id,
                       title,amount_minor,currency,approval_fingerprint,
                       approval_revision,enabled
                FROM fame_live.catalog
                WHERE listing_id = %s FOR UPDATE
            """, (listing_id,))
            catalog_row = cur.fetchone()
            if catalog_row is None:
                raise PurchaseRejected("LIVE_CATALOG_NOT_FOUND")

            cur.execute("""
                SELECT intent_id,order_id,listing_id,buyer_profile_id,
                       seller_profile_id,seller_stripe_account_id,title,
                       currency,amount_minor,fee_minor,approval_fingerprint,
                       approval_revision,state,stripe_session_id
                FROM fame_live.purchase_intents
                WHERE order_id = %s FOR UPDATE
            """, (uid,))
            intent_row = cur.fetchone()
            if intent_row is None:
                raise PurchaseRejected("LIVE_ORDER_NOT_FOUND")
            if intent_row[2] != listing_id:
                raise PurchaseRejected("LIVE_CHECKOUT_LISTING_CHANGED")

            _validate_claim_transition(intent_row[12], intent_row[13])
            authorization = verify_checkout_rows(
                catalog_row, intent_row, snapshot, verified_buyer_profile_id
            )

            cur.execute("""
                UPDATE fame_live.purchase_intents
                   SET state = 'CREATING', updated_at = now()
                 WHERE order_id = %s AND state = 'AUTHORIZED'
                   AND stripe_session_id IS NULL
            """, (uid,))
            if cur.rowcount != 1:
                raise PurchaseRejected("LIVE_CHECKOUT_CLAIM_CONFLICT")

    # Stable across processes; no user-controlled values in the key.
    # Stripe creation/recovery will be a separately gated component.
    return CheckoutClaim(
        authorization=authorization,
        stripe_idempotency_key="fame-live-checkout-" + str(uid),
    )

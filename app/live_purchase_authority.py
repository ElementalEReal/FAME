"""FAME LIVE purchase-intent persistence, NOT a publicly callable checkout endpoint.

Only trusted server-side code may call create_purchase_intent, passing a buyer
identity obtained from verified authentication rather than a browser claim.
The LIVE catalog must be maintained by a separate trusted approval workflow.

No Stripe calls, HTTP routes, or implicit environment variable loading.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from uuid import UUID, uuid4

from app.live_db import live_database
from app.live_policy import Catalog, Intent, PurchaseRejected, authorize


@dataclass(frozen=True)
class AuthorizedOrder:
    intent_id: UUID
    order_id: UUID
    state: str
    amount_minor: int
    fee_minor: int
    reused: bool


def require_uuid4(value: str | UUID) -> UUID:
    try:
        result = UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise PurchaseRejected("CHECKOUT_INTENT_INVALID") from exc
    if result.version != 4 or result.variant != "specified in RFC 4122":
        raise PurchaseRejected("CHECKOUT_INTENT_INVALID")
    return result


def _row_to_order(row: tuple, reused: bool) -> AuthorizedOrder:
    return AuthorizedOrder(
        intent_id=row[0], order_id=row[1], state=row[2],
        amount_minor=row[3], fee_minor=row[4], reused=reused,
    )


def create_purchase_intent(*, intent_id: str | UUID, listing_id: str,
                           buyer_profile_id: str) -> AuthorizedOrder:
    """Create or recover a single immutable, server-authorized purchase order.

    Caller MUST authenticate the buyer independently and MUST NOT expose this
    function to untrusted client data without server-side authentication.
    Enabling requires explicit FAME_LIVE_INTENTS_ENABLED=1 in this process;
    LIVE Stripe checkout remains disabled regardless of this setting.

    The per-intent advisory lock serializes concurrent calls with the same UUID,
    and the catalog row lock serializes listing edits by cooperating DB writers.
    Revocation/inventory updates MUST acquire the same catalog row lock.
    """
    if os.getenv("FAME_LIVE_INTENTS_ENABLED") != "1":
        raise PurchaseRejected("LIVE_INTENTS_DISABLED")
    uid = require_uuid4(intent_id)
    # This function intentionally never reads a price or seller from a caller.
    with live_database(read_only=False) as conn:
        # Existing live_db creates an explicit outer transaction. Lock is scoped
        # to that transaction and will be released even on rollback.
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (str(uid),))
            cur.execute("""
                SELECT listing_id, seller_profile_id, seller_stripe_account_id,
                       title, amount_minor, currency, approval_fingerprint,
                       approval_revision, enabled
                  FROM fame_live.catalog
                 WHERE listing_id = %s FOR UPDATE
            """, (listing_id,))
            raw = cur.fetchone()
            if raw is None:
                raise PurchaseRejected("LIVE_LISTING_NOT_FOUND")
            catalog = Catalog(*raw)
            intent = Intent(uid, listing_id, buyer_profile_id,
                            catalog.seller_profile_id, catalog.amount_minor,
                            catalog.approval_revision, catalog.approval_fingerprint)
            decision = authorize(catalog, intent)
            cur.execute("""
                SELECT intent_id, order_id, state, amount_minor, fee_minor,
                       listing_id, buyer_profile_id, seller_profile_id,
                       seller_stripe_account_id, title, currency,
                       approval_fingerprint, approval_revision
                  FROM fame_live.purchase_intents
                 WHERE intent_id = %s FOR UPDATE
            """, (uid,))
            previous = cur.fetchone()
            if previous:
                expected = (
                    uid, previous[1], previous[2], decision['amount_minor'],
                    decision['fee_minor'], decision['listing_id'],
                    decision['buyer_profile_id'], decision['seller_profile_id'],
                    decision['seller_stripe_account_id'], decision['title'],
                    decision['currency'], decision['approval_fingerprint'],
                    decision['approval_revision'],
                )
                if previous != expected:
                    raise PurchaseRejected("CHECKOUT_INTENT_CONFLICT")
                return _row_to_order(previous, reused=True)

            order_id = uuid4()
            cur.execute("""
                INSERT INTO fame_live.purchase_intents (
                    intent_id, order_id, listing_id, buyer_profile_id,
                    seller_profile_id, seller_stripe_account_id, title,
                    currency, amount_minor, fee_minor, approval_fingerprint,
                    approval_revision, state
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'AUTHORIZED'
                )
                RETURNING intent_id, order_id, state, amount_minor, fee_minor
            """, (
                uid, order_id, decision['listing_id'], decision['buyer_profile_id'],
                decision['seller_profile_id'], decision['seller_stripe_account_id'],
                decision['title'], decision['currency'], decision['amount_minor'],
                decision['fee_minor'], decision['approval_fingerprint'],
                decision['approval_revision'],
            ))
            return _row_to_order(cur.fetchone(), reused=False)

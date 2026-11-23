"""FAME LIVE Stripe Checkout Session creation and durable binding.

Server-only, disabled by default. Caller passes a successful CheckoutClaim
obtained from claim_live_checkout. Do NOT mount as a public endpoint.

Critical invariant: once a claim enters CREATING, failure or uncertainty is
reconciled separately. This module never automatically retries Stripe creation.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from uuid import UUID

from app.live_checkout_claim import CheckoutClaim
from app.live_db import live_database
from app.live_policy import PurchaseRejected

_SESSION_ID = re.compile(r"cs_live_[A-Za-z0-9]+\Z")
_ACCOUNT_ID = re.compile(r"acct_[A-Za-z0-9]+\Z")


@dataclass(frozen=True)
class BoundCheckout:
    order_id: UUID
    session_id: str
    checkout_url: str
    state: str = "PENDING"


def _require_checkout_enabled():
    if os.getenv("FAME_LIVE_CHECKOUT_CREATE_ENABLED") != "1":
        raise PurchaseRejected("LIVE_CHECKOUT_CREATE_DISABLED")


def _controlled_url(var):
    value = os.getenv(var, "")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname not in
            ("elementaleye.co", "www.elementaleye.co") or
            parsed.username is not None or parsed.password is not None or
            parsed.fragment or not parsed.path.startswith("/")):
        raise PurchaseRejected("LIVE_CHECKOUT_REDIRECT_INVALID")
    return value


def _stripe_create_session(claim: CheckoutClaim):
    """Call platform Stripe LIVE account, never browser-supplied credentials.

    No automatic retry. Network errors mean an ambiguous outcome and CREATING
    must remain held for manual/provider-backed reconciliation.
    """
    key = os.getenv("FAME_LIVE_STRIPE_SECRET_KEY", "")
    if not key.startswith("sk_live_"):
        raise PurchaseRejected("LIVE_STRIPE_CREDENTIAL_UNAVAILABLE")
    a = claim.authorization
    if (not _ACCOUNT_ID.fullmatch(a.seller_stripe_account_id) or
            a.currency != "usd" or not (50 <= a.amount_minor <= 10_000_000) or
            not (0 <= a.fee_minor < a.amount_minor)):
        raise PurchaseRejected("LIVE_CHECKOUT_FINANCIAL_VALUES_INVALID")
    success = _controlled_url("FAME_LIVE_CHECKOUT_SUCCESS_URL")
    cancel = _controlled_url("FAME_LIVE_CHECKOUT_CANCEL_URL")
    success += ("&" if "?" in success else "?") + "session_id={CHECKOUT_SESSION_ID}"
    fields = {
        "mode": "payment",
        "payment_method_types[0]": "card",
        "line_items[0][price_data][currency]": "usd",
        "line_items[0][price_data][unit_amount]": str(a.amount_minor),
        "line_items[0][price_data][product_data][name]": a.title,
        "line_items[0][quantity]": "1",
        "payment_intent_data[application_fee_amount]": str(a.fee_minor),
        "payment_intent_data[transfer_data][destination]": a.seller_stripe_account_id,
        "payment_intent_data[metadata][fame_order_id]": str(a.order_id),
        "metadata[fame_order_id]": str(a.order_id),
        "metadata[fame_intent_id]": str(a.intent_id),
        "success_url": success,
        "cancel_url": cancel,
    }
    req = Request(
        "https://api.stripe.com/v1/checkout/sessions",
        data=urlencode(fields).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": claim.stripe_idempotency_key,
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=15) as response:
            raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("Stripe response exceeded limit")
        return json.loads(raw)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise PurchaseRejected("LIVE_STRIPE_CREATE_OUTCOME_UNCERTAIN") from exc


def verify_stripe_session(session, claim: CheckoutClaim):
    """Validates Stripe response identity and totals, never proof of payment."""
    if type(claim) is not CheckoutClaim:
        raise PurchaseRejected("LIVE_CHECKOUT_CLAIM_REQUIRED")
    a = claim.authorization
    if not isinstance(session, dict):
        raise PurchaseRejected("LIVE_CHECKOUT_SESSION_INVALID")
    sid = session.get("id")
    link = session.get("url")
    if not isinstance(sid, str) or not _SESSION_ID.fullmatch(sid):
        raise PurchaseRejected("LIVE_CHECKOUT_SESSION_INVALID")
    parsed = urlsplit(link) if isinstance(link, str) else None
    if (parsed is None or parsed.scheme != "https" or
            parsed.hostname != "checkout.stripe.com" or
            parsed.username is not None or parsed.password is not None):
        raise PurchaseRejected("LIVE_CHECKOUT_SESSION_URL_INVALID")
    if (session.get("livemode") is not True or
            session.get("mode") != "payment" or
            session.get("currency") != "usd" or
            type(session.get("amount_total")) is not int or
            session["amount_total"] != a.amount_minor or
            session.get("status") != "open"):
        raise PurchaseRejected("LIVE_CHECKOUT_SESSION_MISMATCH")
    metadata = session.get("metadata") or {}
    if (not isinstance(metadata, dict) or
            metadata.get("fame_order_id") != str(a.order_id) or
            metadata.get("fame_intent_id") != str(a.intent_id)):
        raise PurchaseRejected("LIVE_CHECKOUT_SESSION_ORDER_MISMATCH")
    return sid, link


def bind_live_checkout_session(claim: CheckoutClaim, session) -> BoundCheckout:
    """Atomically bind only the Session for the claimed, immutable order."""
    _require_checkout_enabled()
    sid, link = verify_stripe_session(session, claim)
    a = claim.authorization
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE fame_live.purchase_intents
                   SET stripe_session_id=%s, state='PENDING',updated_at=now()
                 WHERE order_id=%s AND intent_id=%s AND state='CREATING'
                   AND stripe_session_id IS NULL
                   AND listing_id=%s AND buyer_profile_id IS NOT NULL
                   AND seller_stripe_account_id=%s AND title=%s
                   AND amount_minor=%s AND fee_minor=%s AND currency='usd'
                   AND approval_fingerprint=%s AND approval_revision=%s
                RETURNING order_id
            """, (
                sid, a.order_id, a.intent_id, a.listing_id,
                a.seller_stripe_account_id, a.title, a.amount_minor,
                a.fee_minor, a.approval_fingerprint, a.approval_revision,
            ))
            if cur.fetchone() != (a.order_id,):
                raise PurchaseRejected("LIVE_CHECKOUT_BIND_RECONCILIATION_REQUIRED")
    return BoundCheckout(a.order_id, sid, link)


def reserve_live_dispatch(claim: CheckoutClaim):
    """Durably consume the one permitted provider-send attempt for an order.

    The UNIQUE order_id persists beyond Stripe's idempotency retention window.
    Any crash after this commit requires a separate, audited reconciliation.
    """
    _require_checkout_enabled()
    if type(claim) is not CheckoutClaim:
        raise PurchaseRejected("LIVE_CHECKOUT_CLAIM_REQUIRED")
    a = claim.authorization
    expected_key = "fame-live-checkout-" + str(a.order_id)
    if claim.stripe_idempotency_key != expected_key:
        raise PurchaseRejected("LIVE_CHECKOUT_IDEMPOTENCY_KEY_INVALID")
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO fame_live.checkout_dispatch_attempts
                    (order_id, intent_id, idempotency_key)
                SELECT order_id, intent_id, %s
                  FROM fame_live.purchase_intents
                 WHERE order_id=%s AND intent_id=%s AND state='CREATING'
                   AND stripe_session_id IS NULL
                   AND listing_id=%s AND seller_stripe_account_id=%s
                   AND title=%s AND amount_minor=%s AND fee_minor=%s
                   AND currency='usd' AND approval_fingerprint=%s
                   AND approval_revision=%s
                ON CONFLICT (order_id) DO NOTHING
                RETURNING order_id
            """, (
                expected_key, a.order_id, a.intent_id, a.listing_id,
                a.seller_stripe_account_id, a.title, a.amount_minor, a.fee_minor,
                a.approval_fingerprint, a.approval_revision,
            ))
            if cur.fetchone() != (a.order_id,):
                raise PurchaseRejected("LIVE_CHECKOUT_DISPATCH_ALREADY_ATTEMPTED")


def create_and_bind_live_checkout(claim: CheckoutClaim, *, create_session=None):
    """One attempt only; never reclaims or automatically retries CREATING.

    Invoked directly by trusted server code immediately after a successful claim.
    A crash or lost response leaves CREATING for separate reconciliation.
    """
    _require_checkout_enabled()
    if type(claim) is not CheckoutClaim:
        raise PurchaseRejected("LIVE_CHECKOUT_CLAIM_REQUIRED")
    a = claim.authorization
    if claim.stripe_idempotency_key != "fame-live-checkout-" + str(a.order_id):
        raise PurchaseRejected("LIVE_CHECKOUT_IDEMPOTENCY_KEY_INVALID")
    create = _stripe_create_session if create_session is None else create_session
    if not callable(create):
        raise PurchaseRejected("LIVE_CHECKOUT_PROVIDER_INVALID")
    # Commit the durable dispatch record before making any external call.
    # Concurrent/replayed invocations fail BEFORE reaching Stripe.
    reserve_live_dispatch(claim)
    try:
        session = create(claim)
    except PurchaseRejected:
        raise
    except Exception as exc:
        raise PurchaseRejected("LIVE_STRIPE_CREATE_OUTCOME_UNCERTAIN") from exc
    return bind_live_checkout_session(claim, session)

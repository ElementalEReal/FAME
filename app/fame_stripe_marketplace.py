"""FAME F2.3/F2.4 Marketplace – TEST ONLY.

Trusted Wix backend -> HMAC-signed Render commands.
This module is a router, not the FastAPI app entrypoint.
Mount using app.include_router(router) in the deployed Render application.

Required environment:
  FAME_STRIPE_BRIDGE_SECRET (same as Wix Secrets Manager; >=32 chars)
  FAME_STRIPE_MODE=test
  FAME_STRIPE_SECRET_KEY=sk_test_... or rk_test_...
  FAME_STRIPE_DATABASE_URL (or DATABASE_URL)
  FAME_STRIPE_SUCCESS_URL / FAME_STRIPE_CANCEL_URL (HTTPS)
  FAME_STRIPE_ONBOARDING_RETURN_URL (HTTPS)
Optional: FAME_MARKETPLACE_FEE_BPS (default 500, limited to 0..1000).

IMPORTANT: Seller/listing/buyer permissions must be checked by Wix. This API
must never be called directly by browser/iframe clients. Marketplace payment
success is established only by verified Stripe webhook events, never by a
redirect or a successfully created Checkout Session.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from urllib import error as urlerror, request as urlrequest
from urllib.parse import quote

import psycopg
import stripe
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/v1/stripe/marketplace", tags=["FAME Stripe TEST"])
log = logging.getLogger("fame.stripe.marketplace")
STRIPE_V2_VERSION = "2026-10-28.endive"  # Existing, deployed Accounts v2 version; do not silently alter.


def db_url() -> str:
    value = os.getenv("FAME_STRIPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not value:
        raise HTTPException(503, "Database unavailable")
    return value


def configure() -> None:
    key = os.getenv("FAME_STRIPE_SECRET_KEY", "")
    if os.getenv("FAME_STRIPE_MODE") != "test" or not key.startswith(("sk_test_", "rk_test_")):
        raise HTTPException(503, "Test mode not configured")
    stripe.api_key = key


def origin_url(name: str) -> str:
    """Only server-controlled HTTPS return URLs; never use a URL from caller."""
    value = os.getenv(name, "").strip().rstrip("/")
    if not value.startswith("https://"):
        raise HTTPException(503, f"{name} must be an HTTPS URL")
    return value


async def guard(request: Request) -> None:
    """HMAC signature, 5-minute freshness, durable nonce replay prevention."""
    secret = os.getenv("FAME_STRIPE_BRIDGE_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "Bridge not configured")

    ts = request.headers.get("x-fame-timestamp", "")
    nonce = request.headers.get("x-fame-nonce", "")
    supplied = request.headers.get("x-fame-signature", "")
    try:
        parsed_ts = int(ts)
    except (TypeError, ValueError):
        raise HTTPException(401, "Unauthorized") from None
    if not ts.isdecimal() or abs(time.time() - parsed_ts) > 300 or not (16 <= len(nonce) <= 128):
        raise HTTPException(401, "Expired or invalid request")

    body = await request.body()
    digest = hashlib.sha256(body).hexdigest()
    message = "\n".join([request.method.upper(), request.url.path, ts, nonce, digest])
    expected = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(401, "Unauthorized")

    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fame_stripe.bridge_nonces WHERE created_at < now() - interval '1 day'")
            cur.execute(
                "INSERT INTO fame_stripe.bridge_nonces(nonce) VALUES (%s) ON CONFLICT DO NOTHING",
                (nonce,),
            )
            if cur.rowcount != 1:
                raise HTTPException(409, "Request already used")
    configure()


class SellerRequest(BaseModel):
    seller_key: str = Field(min_length=3, max_length=200)


class CheckoutRequest(BaseModel):
    checkout_request_id: uuid.UUID  # Stable UUID; Wix MUST reuse on retries.
    listing_id: str = Field(min_length=1, max_length=200)
    seller_key: str = Field(min_length=3, max_length=200)
    buyer_key: str = Field(min_length=3, max_length=200)
    item_title: str = Field(min_length=3, max_length=150)
    amount_minor: int = Field(ge=50, le=10_000_000)
    currency: str = "usd"


def stripe_v2(method: str, path: str, data=None, idempotency_key=None):
    """Existing Stripe Accounts v2 helper. Never log credentials or full responses."""
    key = os.getenv("FAME_STRIPE_SECRET_KEY", "")
    if os.getenv("FAME_STRIPE_MODE") != "test" or not key.startswith("sk_test_"):
        raise HTTPException(503, "Accounts v2 requires a Stripe TEST secret key")
    headers = {
        "Authorization": "Bearer " + key,
        "Stripe-Version": STRIPE_V2_VERSION,
        "Accept": "application/json",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    req = urlrequest.Request(
        "https://api.stripe.com" + path,
        data=(json.dumps(data).encode("utf-8") if data is not None else None),
        method=method,
        headers=headers,
    )
    try:
        with urlrequest.urlopen(req, timeout=18) as response:
            return json.load(response)
    except urlerror.HTTPError as exc:
        code = "unknown"
        field_paths = []
        try:
            err_data = json.loads(exc.read().decode("utf-8"))
            if isinstance(err_data, dict):
                err = err_data.get("error")
                if not isinstance(err, dict):
                    err = err_data
                code = str(err.get("code", "unknown"))[:80]
                fields = err.get("invalid_fields") or err_data.get("invalid_fields") or []
                if isinstance(fields, list):
                    for field in fields[:10]:
                        path_value = (field.get("field") or field.get("path") or field.get("name")) if isinstance(field, dict) else field
                        if isinstance(path_value, str) and len(path_value) <= 200:
                            field_paths.append(path_value)
        except (ValueError, UnicodeError):
            pass
        log.error(
            "STRIPE_V2_REQUEST_FAILED method=%s status=%s code=%s invalid_fields=%s",
            method, exc.code, code, field_paths,
        )
        raise HTTPException(502, "FAME_STRIPE_V2_PROVIDER_ERROR") from None
    except (urlerror.URLError, TimeoutError):
        log.error("STRIPE_V2_TRANSPORT_FAILURE method=%s", method)
        raise HTTPException(503, "FAME_STRIPE_TEMPORARILY_UNAVAILABLE") from None


def v2_account_status(account_id: str) -> dict:
    from urllib.parse import urlencode
    query = urlencode([
        ("include[0]", "configuration.merchant"),
        ("include[1]", "configuration.recipient"),
        ("include[2]", "requirements"),
    ])
    account = stripe_v2("GET", "/v2/core/accounts/" + quote(account_id, safe="") + "?" + query)
    if account.get("livemode") is not False:
        raise HTTPException(409, "TEST_ACCOUNT_REQUIRED")
    conf = account.get("configuration") or {}
    merchant = conf.get("merchant") or {}
    recipient = conf.get("recipient") or {}
    merchant_caps = merchant.get("capabilities") or {}
    recipient_caps = recipient.get("capabilities") or {}
    transfers = (recipient_caps.get("stripe_balance") or {}).get("stripe_transfers") or {}
    payouts = (merchant_caps.get("stripe_balance") or {}).get("payouts") or {}
    payments_ready = (merchant_caps.get("card_payments") or {}).get("status") == "active"
    transfers_ready = transfers.get("status") == "active"
    payouts_ready = payouts.get("status") == "active"
    ready = payments_ready and transfers_ready and payouts_ready
    return {
        "connected": True,
        "charges_enabled": payments_ready,
        "payouts_enabled": transfers_ready and payouts_ready,
        "details_submitted": ready,
        "ready_for_checkout": ready,
        "merchant_card_payments": (merchant_caps.get("card_payments") or {}).get("status", "unknown"),
        "recipient_stripe_transfers": transfers.get("status", "unknown"),
        "merchant_payouts": payouts.get("status", "unknown"),
    }


@router.post("/seller/onboard")
async def seller_onboard(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s",
                (payload.seller_key,),
            )
            row = cur.fetchone()

    if row:
        account_id = row[0]
        before = v2_account_status(account_id)
        if before["recipient_stripe_transfers"] == "unknown":
            stripe_v2(
                "POST",
                "/v2/core/accounts/" + quote(account_id, safe=""),
                {"configuration": {"recipient": {"capabilities": {
                    "stripe_balance": {"stripe_transfers": {"requested": True}}
                }}}},
                idempotency_key=("fame-v2-recipient-request-v1-" + hashlib.sha256(account_id.encode()).hexdigest()),
            )
            # Capability requests are not proof of activation.
            v2_account_status(account_id)
    else:
        # Preserve existing Connect v2 Express merchant-only onboarding model.
        account = stripe_v2(
            "POST", "/v2/core/accounts",
            {
                "dashboard": "express",
                "identity": {"country": "us"},
                "configuration": {"merchant": {"capabilities": {"card_payments": {"requested": True}}}},
                "defaults": {"responsibilities": {
                    "fees_collector": "application", "losses_collector": "application"
                }},
                "metadata": {"fame_seller_key": payload.seller_key},
            },
            idempotency_key=("fame-v2-merchant-only-v1-" + hashlib.sha256(payload.seller_key.encode()).hexdigest()),
        )
        if account.get("livemode") is not False or not str(account.get("id", "")).startswith("acct_"):
            raise HTTPException(502, "INVALID_STRIPE_TEST_ACCOUNT")
        account_id = account["id"]
        with psycopg.connect(db_url(), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO fame_stripe.seller_accounts (seller_key,stripe_account_id) "
                    "VALUES (%s,%s) ON CONFLICT (seller_key) DO NOTHING",
                    (payload.seller_key, account_id),
                )
                cur.execute(
                    "SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s",
                    (payload.seller_key,),
                )
                account_id = cur.fetchone()[0]

    try:
        link = stripe.AccountLink.create(
            account=account_id,
            type="account_onboarding",
            refresh_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"),
            return_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"),
        )
    except Exception as exc:
        log.error("FAME_STRIPE_ACCOUNT_LINK_FAILED type=%s", type(exc).__name__)
        raise HTTPException(502, "FAME_STRIPE_ONBOARDING_UNAVAILABLE") from None
    return {"url": link.url, "status": "ONBOARDING_REQUIRED"}


@router.post("/seller/status")
async def seller_status(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s",
                (payload.seller_key,),
            )
            record = cur.fetchone()
    if not record:
        return {
            "connected": False,
            "charges_enabled": False,
            "payouts_enabled": False,
            "ready_for_checkout": False,
        }
    state = v2_account_status(record[0])
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE fame_stripe.seller_accounts "
                "SET charges_enabled=%s,payouts_enabled=%s,details_submitted=%s,updated_at=now() "
                "WHERE seller_key=%s",
                (state["charges_enabled"], state["payouts_enabled"], state["details_submitted"], payload.seller_key),
            )
    return state


def _validate_test_session(session, expected_order_id: str) -> None:
    """A session URL is not evidence of payment."""
    sid = str(getattr(session, "id", ""))
    link = str(getattr(session, "url", ""))
    if getattr(session, "livemode", None) is not False or not sid.startswith("cs_test_"):
        raise HTTPException(502, "Stripe TEST session could not be verified")
    if not link.startswith("https://checkout.stripe.com/"):
        raise HTTPException(502, "Stripe TEST session URL unavailable")
    metadata = getattr(session, "metadata", None) or {}
    if metadata.get("fame_order_id") != expected_order_id:
        raise HTTPException(502, "Stripe session order mismatch")


def _session_payload(session, order_id: str) -> dict:
    _validate_test_session(session, order_id)
    return {
        "url": session.url,
        "order_id": order_id,
        "stripe_session_id": session.id,
        "mode": "test",
        "livemode": False,
    }


@router.post("/checkout")
async def create_checkout(request: Request, payload: CheckoutRequest):
    await guard(request)
    if payload.currency != "usd" or payload.seller_key == payload.buyer_key:
        raise HTTPException(400, "Unsupported purchase")

    # FAME fee policy: marketplace is precisely 500 bps (5%), half-up to
    # the nearest cent. Never stack production fees on this transaction.
    if os.getenv("FAME_MARKETPLACE_FEE_BPS", "500") != "500":
        raise HTTPException(503, "Unexpected FAME fee policy configuration")
    fee_minor = (payload.amount_minor * 500 + 5_000) // 10_000
    if fee_minor >= payload.amount_minor:
        raise HTTPException(400, "Invalid checkout fee")

    with psycopg.connect(db_url(), connect_timeout=5) as lookup_conn:
        with lookup_conn.cursor() as cur:
            cur.execute(
                "SELECT stripe_account_id FROM fame_stripe.seller_accounts "
                "WHERE seller_key=%s", (payload.seller_key,)
            )
            seller = cur.fetchone()
    if not seller:
        raise HTTPException(409, "Seller must attach an account")
    account = v2_account_status(seller[0])
    if not account["ready_for_checkout"]:
        raise HTTPException(409, "Seller onboarding incomplete")

    request_id = str(payload.checkout_request_id)

    # A session-level PostgreSQL advisory lock serializes legitimate retries
    # of the SAME business intent across Render workers. It survives commits
    # while this connection is open, and releases when the connection closes.
    # Its hash may collide harmlessly (extra serialization only).
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pg_advisory_lock(hashtextextended(%s, 0))",
                    (request_id,)
                )
            conn.commit()
            with conn.cursor() as cur:
                new_order_id = str(uuid.uuid4())
                cur.execute(
                    "INSERT INTO fame_stripe.marketplace_orders "
                    "(order_id,checkout_request_id,listing_id,buyer_key,seller_key,"
                    "item_title,amount_minor,fee_minor,currency,status) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'usd','CREATING') "
                    "ON CONFLICT (checkout_request_id) DO NOTHING",
                    (new_order_id, payload.checkout_request_id, payload.listing_id,
                     payload.buyer_key, payload.seller_key, payload.item_title,
                     payload.amount_minor, fee_minor)
                )
                cur.execute(
                    "SELECT order_id::text,listing_id,buyer_key,seller_key,"
                    "item_title,amount_minor,fee_minor,currency,status,stripe_session_id "
                    "FROM fame_stripe.marketplace_orders "
                    "WHERE checkout_request_id=%s", (payload.checkout_request_id,)
                )
                existing = cur.fetchone()
            conn.commit()
            if not existing:
                raise HTTPException(503, "Checkout intent persistence unavailable")

            (order_id, listing_id, buyer_key, seller_key, title,
             amount_minor, stored_fee, currency, status, existing_session) = existing
            if (listing_id != payload.listing_id or buyer_key != payload.buyer_key or
                seller_key != payload.seller_key or title != payload.item_title or
                amount_minor != payload.amount_minor or stored_fee != fee_minor or
                currency != "usd"):
                raise HTTPException(409, "Checkout request ID is already bound to another purchase")

            if status in ("PAID", "REFUNDED", "PARTIALLY_REFUNDED", "FAILED"):
                raise HTTPException(409, "Checkout intent is no longer reusable")

            if existing_session:
                # A previously created Checkout Session is the only valid
                # session for this request ID. Do not silently create another.
                try:
                    session = stripe.checkout.Session.retrieve(existing_session)
                except Exception as exc:
                    log.error("FAME_CHECKOUT_RECOVER_SESSION_FAILED type=%s",
                              type(exc).__name__)
                    raise HTTPException(503, "Checkout session recovery unavailable") from None
                _validate_test_session(session, order_id)
                if getattr(session, "status", None) != "open":
                    raise HTTPException(409, "Checkout session is no longer open")
                return _session_payload(session, order_id)

            if status != "CREATING":
                raise HTTPException(409, "Checkout intent cannot be resumed")

            # Stable Stripe key uses the persisted order ID, so retries after
            # a timeout/Render restart retrieve the same Session from Stripe
            # within Stripe's idempotency retention window. Once that period
            # has elapsed, automated retries must be held for reconciliation;
            # do not issue a fresh session under the same intent.
            created_at = None
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT created_at FROM fame_stripe.marketplace_orders WHERE order_id=%s",
                    (order_id,)
                )
                created_at = cur.fetchone()[0]
            conn.commit()
            from datetime import datetime, timezone, timedelta
            if created_at < datetime.now(timezone.utc) - timedelta(hours=20):
                raise HTTPException(409, "Checkout request requires reconciliation")

            try:
                success_url = origin_url("FAME_STRIPE_SUCCESS_URL")
                success_url += ("&" if "?" in success_url else "?") + "session_id={CHECKOUT_SESSION_ID}"
                session = stripe.checkout.Session.create(
                    mode="payment",
                    payment_method_types=["card"],
                    line_items=[{
                        "price_data": {
                            "currency": "usd",
                            "unit_amount": amount_minor,
                            "product_data": {"name": title},
                        },
                        "quantity": 1,
                    }],
                    payment_intent_data={
                        "application_fee_amount": stored_fee,
                        "transfer_data": {"destination": seller[0]},
                        "metadata": {"fame_order_id": order_id},
                    },
                    metadata={"fame_order_id": order_id},
                    success_url=success_url,
                    cancel_url=origin_url("FAME_STRIPE_CANCEL_URL"),
                    idempotency_key="fame-checkout-" + order_id,
                )
                _validate_test_session(session, order_id)
            except HTTPException:
                raise
            except Exception as exc:
                # Ambiguous Stripe/network failures cannot be labeled FAILED:
                # Stripe may already have created the session. Preserve the
                # stable order and retry using the same Stripe key.
                log.error("FAME_CHECKOUT_CREATION_UNCERTAIN type=%s",
                          type(exc).__name__)
                raise HTTPException(503, "Checkout temporarily unavailable") from None

            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE fame_stripe.marketplace_orders "
                    "SET stripe_session_id=%s,status='PENDING',updated_at=now() "
                    "WHERE order_id=%s AND status='CREATING' "
                    "AND stripe_session_id IS NULL",
                    (session.id, order_id)
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    raise HTTPException(409, "Checkout state changed; reconciliation required")
            conn.commit()
            log.info("FAME_CHECKOUT_TEST_SESSION_CREATED_OR_RECOVERED")
            return _session_payload(session, order_id)
        finally:
            # Closing the connection also releases the session advisory lock.
            # Explicit unlock is useful when connection cleanup is deferred.
            try:
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                        (request_id,)
                    )
                conn.commit()
            except Exception:
                log.error("FAME_CHECKOUT_ADVISORY_LOCK_CLEANUP_FAILED")


@router.post("/seller/orders")
async def seller_orders(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT order_id::text,listing_id,item_title,amount_minor,fee_minor, "
                "refunded_minor,status,created_at::text FROM fame_stripe.marketplace_orders "
                "WHERE seller_key=%s ORDER BY created_at DESC LIMIT 40",
                (payload.seller_key,),
            )
            rows = cur.fetchall()
    fields = [
        "order_id", "listing_id", "title", "amount_minor", "platform_fee_minor",
        "refunded_minor", "status", "created_at",
    ]
    return {
        "orders": [dict(zip(fields, row)) for row in rows],
        "note": "Order amounts and nominal FAME fees; not a verified bank payout or net earnings balance.",
    }

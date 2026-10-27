"""FAME F2.3/2.4 TEST ONLY. Trusted Wix backend -> signed Render commands.

Requires environment FAME_STRIPE_BRIDGE_SECRET shared with Wix Secrets Manager.
Seller and listing access MUST be resolved in authenticated Wix backend;
never call this route directly from an iframe or a browser.
"""
import hashlib
import hmac
import os
import time
import uuid
from typing import Any

import psycopg
import stripe
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/v1/stripe/marketplace", tags=["FAME Stripe TEST"])


def db_url():
    value = os.getenv("FAME_STRIPE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not value:
        raise HTTPException(503, "Database unavailable")
    return value


def configure():
    key = os.getenv("FAME_STRIPE_SECRET_KEY", "")
    if os.getenv("FAME_STRIPE_MODE") != "test" or not key.startswith(("sk_test_", "rk_test_")):
        raise HTTPException(503, "Test mode not configured")
    stripe.api_key = key


def origin_url(key):
    # Fixed trusted URLs; never accept arbitrary return/success URLs from a caller.
    u = os.getenv(key, "").rstrip("/")
    if not u.startswith("https://"):
        raise HTTPException(503, f"{key} must be an HTTPS URL")
    return u


async def guard(request: Request):
    """Shared-secret HMAC, timestamp and database-backed nonce replay defense."""
    secret = os.getenv("FAME_STRIPE_BRIDGE_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(503, "Bridge not configured")
    ts, nonce, signature = (request.headers.get(k, "") for k in
                            ("x-fame-timestamp", "x-fame-nonce", "x-fame-signature"))
    try:
        t = int(ts)
    except ValueError:
        raise HTTPException(401, "Unauthorized")
    if abs(time.time() - t) > 300 or len(nonce) < 16 or len(nonce) > 128:
        raise HTTPException(401, "Expired or invalid request")
    body = await request.body()
    digest = hashlib.sha256(body).hexdigest()
    message = "\n".join([request.method.upper(), request.url.path, ts, nonce, digest])
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Unauthorized")
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fame_stripe.bridge_nonces WHERE created_at < now() - interval '1 day'")
            cur.execute("INSERT INTO fame_stripe.bridge_nonces(nonce) VALUES (%s) ON CONFLICT DO NOTHING", (nonce,))
            if cur.rowcount != 1:
                raise HTTPException(409, "Request already used")
    configure()


class SellerRequest(BaseModel):
    seller_key: str = Field(min_length=3, max_length=200)


class CheckoutRequest(BaseModel):
    listing_id: str = Field(min_length=1, max_length=200)
    seller_key: str = Field(min_length=3, max_length=200)
    buyer_key: str = Field(min_length=3, max_length=200)
    item_title: str = Field(min_length=3, max_length=150)
    amount_minor: int = Field(ge=50, le=10000000)
    currency: str = "usd"


@router.post("/seller/onboard")
async def seller_onboard(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
            record = cur.fetchone()
    if record:
        account_id = record[0]
    else:
        # Legacy Express-style Connect accounts, US only for initial MVP.
        account = stripe.Account.create(type="express", country="US", capabilities={
            "card_payments": {"requested": True}, "transfers": {"requested": True}},
            metadata={"fame_seller_key": payload.seller_key},
            idempotency_key="fame-seller-" + hashlib.sha256(payload.seller_key.encode()).hexdigest())
        account_id = account.id
        with psycopg.connect(db_url(), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO fame_stripe.seller_accounts (seller_key,stripe_account_id)
                               VALUES (%s,%s) ON CONFLICT (seller_key) DO NOTHING""", (payload.seller_key, account_id))
                cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
                account_id = cur.fetchone()[0]
    link = stripe.AccountLink.create(
        account=account_id, type="account_onboarding",
        refresh_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"),
        return_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"))
    return {"url": link.url, "status": "ONBOARDING_REQUIRED"}


@router.post("/seller/status")
async def seller_status(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
            record = cur.fetchone()
    if not record:
        return {"connected": False, "charges_enabled": False, "payouts_enabled": False}
    account = stripe.Account.retrieve(record[0])
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE fame_stripe.seller_accounts
               SET charges_enabled=%s,payouts_enabled=%s,details_submitted=%s,updated_at=now()
               WHERE seller_key=%s""", (bool(account.charges_enabled), bool(account.payouts_enabled), bool(account.details_submitted), payload.seller_key))
    return {"connected": True, "charges_enabled": bool(account.charges_enabled),
            "payouts_enabled": bool(account.payouts_enabled), "details_submitted": bool(account.details_submitted)}


@router.post("/checkout")
async def create_checkout(request: Request, payload: CheckoutRequest):
    await guard(request)
    if payload.currency.lower() != "usd" or payload.seller_key == payload.buyer_key:
        raise HTTPException(400, "Unsupported purchase")
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
            seller = cur.fetchone()
    if not seller:
        raise HTTPException(409, "Seller must attach an account")
    account = stripe.Account.retrieve(seller[0])
    if not bool(account.charges_enabled) or not bool(account.payouts_enabled):
        raise HTTPException(409, "Seller onboarding incomplete")
    fee_bps = int(os.getenv("FAME_MARKETPLACE_FEE_BPS", "500"))
    if fee_bps < 0 or fee_bps > 1000:
        raise HTTPException(503, "Invalid platform fee configuration")
    fee_minor = payload.amount_minor * fee_bps // 10000
    order_id = str(uuid.uuid4())
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO fame_stripe.marketplace_orders
            (order_id,listing_id,buyer_key,seller_key,item_title,amount_minor,fee_minor)
            VALUES (%s,%s,%s,%s,%s,%s,%s)""", (order_id,payload.listing_id,payload.buyer_key,
                                                   payload.seller_key,payload.item_title,payload.amount_minor,fee_minor))
    try:
        session = stripe.checkout.Session.create(
            mode="payment", payment_method_types=["card"],
            line_items=[{"price_data": {"currency":"usd", "unit_amount":payload.amount_minor,
                "product_data":{"name":payload.item_title}}, "quantity":1}],
            payment_intent_data={"application_fee_amount":fee_minor,
                                 "transfer_data":{"destination":seller[0]},
                                 "metadata":{"fame_order_id":order_id}},
            metadata={"fame_order_id":order_id},
            success_url=origin_url("FAME_STRIPE_SUCCESS_URL")+"?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=origin_url("FAME_STRIPE_CANCEL_URL"),
            idempotency_key="fame-checkout-"+order_id)
    except Exception:
        with psycopg.connect(db_url(), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE fame_stripe.marketplace_orders SET status='FAILED' WHERE order_id=%s", (order_id,))
        raise HTTPException(502, "Unable to create secure checkout")
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE fame_stripe.marketplace_orders
                   SET stripe_session_id=%s,status='PENDING',updated_at=now() WHERE order_id=%s""", (session.id,order_id))
    return {"url":session.url, "order_id":order_id}


@router.post("/seller/orders")
async def seller_orders(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT order_id::text,listing_id,item_title,amount_minor,fee_minor,
                       refunded_minor,status,created_at::text FROM fame_stripe.marketplace_orders
                       WHERE seller_key=%s ORDER BY created_at DESC LIMIT 40""", (payload.seller_key,))
            rows = cur.fetchall()
    fields = ['order_id','listing_id','title','amount_minor','platform_fee_minor','refunded_minor','status','created_at']
    return {'orders':[dict(zip(fields,r)) for r in rows],
            'note':'Order amounts and nominal FAME fees; not a verified bank payout or net earnings balance.'}

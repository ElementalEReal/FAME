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
import json
import logging
from urllib import request as urlrequest, error as urlerror

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





# Stripe Accounts v2 for new connected sellers. v1 account links are interoperable.
# This uses the published v2 REST API, independent of the installed stripe-python version.
STRIPE_V2_VERSION = "2026-10-28.endive"
log = logging.getLogger("fame.stripe.marketplace")


def stripe_v2(method: str, path: str, data=None, idempotency_key=None):
    key = os.getenv("FAME_STRIPE_SECRET_KEY", "")
    if os.getenv("FAME_STRIPE_MODE") != "test" or not key.startswith("sk_test_"):
        raise HTTPException(503, "Accounts v2 requires a Stripe TEST secret key")
    headers = {"Authorization": "Bearer " + key,
               "Stripe-Version": STRIPE_V2_VERSION, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    req = urlrequest.Request("https://api.stripe.com" + path,
                             data=(json.dumps(data).encode("utf-8") if data is not None else None),
                             method=method, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=18) as response:
            return json.load(response)
    except urlerror.HTTPError as exc:
        # Log only validation field paths, never full Stripe responses, request
        # bodies, personal account details, or authentication credentials.
        error_code = "unknown"
        field_paths = []
        try:
            error_data = json.loads(exc.read().decode("utf-8"))
            if isinstance(error_data, dict):
                error_obj = error_data.get("error")
                if not isinstance(error_obj, dict):
                    error_obj = error_data
                error_code = str(error_obj.get("code", "unknown"))[:80]
                invalid_fields = error_obj.get("invalid_fields")
                if invalid_fields is None:
                    invalid_fields = error_data.get("invalid_fields", [])
                if isinstance(invalid_fields, list):
                    for field in invalid_fields[:10]:
                        if isinstance(field, dict):
                            path = field.get("field") or field.get("path") or field.get("name")
                            if isinstance(path, str) and len(path) <= 200:
                                field_paths.append(path)
                        elif isinstance(field, str) and len(field) <= 200:
                            field_paths.append(field)
        except (ValueError, UnicodeError):
            pass
        log.error(
            "STRIPE_V2_REQUEST_FAILED method=%s status=%s code=%s invalid_fields=%s",
            method, exc.code, error_code, field_paths
        )
        raise HTTPException(502, "FAME_STRIPE_V2_PROVIDER_ERROR") from None
    except (urlerror.URLError, TimeoutError):
        log.exception("STRIPE_V2_TRANSPORT_FAILURE")
        raise HTTPException(503, "FAME_STRIPE_TEMPORARILY_UNAVAILABLE") from None


def v2_account_status(account_id):
    from urllib.parse import quote, urlencode
    query = urlencode([("include[0]", "configuration.merchant"),
                       ("include[1]", "configuration.recipient"),
                       ("include[2]", "requirements")])
    account = stripe_v2("GET", "/v2/core/accounts/" + quote(account_id, safe="") + "?" + query)
    if account.get("livemode") is not False:
        raise HTTPException(409, "TEST_ACCOUNT_REQUIRED")
    conf = account.get("configuration") or {}
    merchant = conf.get("merchant") or {}
    recipient = conf.get("recipient") or {}
    mc = merchant.get("capabilities") or {}
    rc = recipient.get("capabilities") or {}
    transfers = (rc.get("stripe_balance") or {}).get("stripe_transfers") or {}
    payouts = (mc.get("stripe_balance") or {}).get("payouts") or {}
    payments_ready = (mc.get("card_payments") or {}).get("status") == "active"
    transfers_ready = transfers.get("status") == "active"
    payouts_ready = payouts.get("status") == "active"
    ready = payments_ready and transfers_ready and payouts_ready
    return {"connected": True, "charges_enabled": payments_ready,
            "payouts_enabled": transfers_ready and payouts_ready,
            "details_submitted": ready, "ready_for_checkout": ready,
            "merchant_card_payments": (mc.get("card_payments") or {}).get("status", "unknown"),
            "recipient_stripe_transfers": transfers.get("status", "unknown"),
            "merchant_payouts": payouts.get("status", "unknown")}


@router.post("/seller/onboard")
async def seller_onboard(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
            row = cur.fetchone()
    if row:
        account_id = row[0]
        # Reuse only the existing, TEST-mode Stripe account. Never create a second seller.
        before = v2_account_status(account_id)
        if before["recipient_stripe_transfers"] == "unknown":
            # Accounts v2: add the Recipient transfer capability separately, rather
            # than combining it with Merchant during account creation.
            # This can be rejected for unsupported Connect configurations;
            # stripe_v2 logs the exact field paths and fails closed on errors.
            from urllib.parse import quote
            stripe_v2(
                "POST",
                "/v2/core/accounts/" + quote(account_id, safe=""),
                {"configuration": {"recipient": {"capabilities": {
                    "stripe_balance": {"stripe_transfers": {"requested": True}}
                }}}},
                idempotency_key="fame-v2-recipient-request-v1-" + hashlib.sha256(account_id.encode()).hexdigest(),
            )
            # A capability request is NOT proof of approval. Checkout remains
            # blocked until a fresh status response reports all capabilities active.
            v2_account_status(account_id)
    else:
        # Express + destination charges: platform bears fee and negative-balance liability.
        # Responsibilities cannot be changed after merchant configuration is added.
        account = stripe_v2("POST", "/v2/core/accounts", {
            "dashboard": "express",
            "identity": {"country": "us"},
            # Merchant-only account creation: Stripe rejected configuration.recipient.
            # Do not assume recipient/transfer permissions; checkout remains fail-closed.
            "configuration": {
                "merchant": {"capabilities": {"card_payments": {"requested": True}}}
            },
            "defaults": {"responsibilities": {
                "fees_collector": "application", "losses_collector": "application"}},
            "metadata": {"fame_seller_key": payload.seller_key}
        }, idempotency_key="fame-v2-merchant-only-v1-" + hashlib.sha256(payload.seller_key.encode()).hexdigest())
        if account.get("livemode") is not False or not str(account.get("id", "")).startswith("acct_"):
            raise HTTPException(502, "INVALID_STRIPE_TEST_ACCOUNT")
        account_id = account["id"]
        with psycopg.connect(db_url(), connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("""INSERT INTO fame_stripe.seller_accounts (seller_key,stripe_account_id)
                               VALUES (%s,%s) ON CONFLICT (seller_key) DO NOTHING""",
                            (payload.seller_key, account_id))
                cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
                account_id = cur.fetchone()[0]
    try:
        link = stripe.AccountLink.create(
            account=account_id, type="account_onboarding",
            refresh_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"),
            return_url=origin_url("FAME_STRIPE_ONBOARDING_RETURN_URL"))
    except stripe.error.StripeError:
        log.exception("FAME_STRIPE_ACCOUNT_LINK_FAILED")
        raise HTTPException(502, "FAME_STRIPE_ONBOARDING_UNAVAILABLE") from None
    return {"url": link.url, "status": "ONBOARDING_REQUIRED"}


@router.post("/seller/status")
async def seller_status(request: Request, payload: SellerRequest):
    await guard(request)
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT stripe_account_id FROM fame_stripe.seller_accounts WHERE seller_key=%s", (payload.seller_key,))
            record = cur.fetchone()
    if not record:
        return {"connected": False, "charges_enabled": False, "payouts_enabled": False,
                "ready_for_checkout": False}
    state = v2_account_status(record[0])
    with psycopg.connect(db_url(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("""UPDATE fame_stripe.seller_accounts
                           SET charges_enabled=%s,payouts_enabled=%s,details_submitted=%s,updated_at=now()
                           WHERE seller_key=%s""",
                        (state["charges_enabled"], state["payouts_enabled"],
                         state["details_submitted"], payload.seller_key))
    return state


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

    account = v2_account_status(seller[0])

    if not account["ready_for_checkout"]:

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

    return {"url":session.url, "order_id":order_id, "stripe_session_id":session.id}





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

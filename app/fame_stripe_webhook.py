"""FAME F2.2 plus F2.3 TEST webhook intake / order observations.

No direct ledger postings, product fulfillment, manual payouts, or refunds occur here.
Mount with app.include_router(router) in app/main.py.
"""
import os
import logging
import json
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
import stripe
import psycopg

log = logging.getLogger("fame.stripe.webhook")
router = APIRouter()

EVENT_TYPES = frozenset({
    "checkout.session.completed",
    "checkout.session.async_payment_succeeded",
    "checkout.session.async_payment_failed",
    "payment_intent.payment_failed",
    "charge.refunded",
    "account.updated",
})


def _settings():
    mode = os.environ.get("FAME_STRIPE_MODE", "").strip()
    api_key = os.environ.get("FAME_STRIPE_SECRET_KEY", "")
    secret = os.environ.get("FAME_STRIPE_WEBHOOK_SECRET", "")
    db_url = os.environ.get("FAME_STRIPE_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if mode != "test":
        raise RuntimeError("F2.2 is test-only; refusing non-test mode")
    if not api_key.startswith(("sk_test_", "rk_test_")):
        raise RuntimeError("Stripe test secret key is missing or mismatched")
    if not secret.startswith("whsec_"):
        raise RuntimeError("Stripe webhook signing secret missing")
    if not db_url:
        raise RuntimeError("Set FAME_STRIPE_DATABASE_URL or DATABASE_URL")
    return secret, db_url


@router.post("/v1/stripe/webhook", include_in_schema=False)
async def stripe_webhook(request: Request):
    try:
        secret, db_url = _settings()
    except RuntimeError:
        log.exception("Stripe intake configuration failed")
        raise HTTPException(503, "Webhook unavailable")

    raw_body = await request.body()
    if len(raw_body) > 1024 * 1024:
        raise HTTPException(413, "Webhook payload too large")
    signature = request.headers.get("stripe-signature")
    if not signature:
        raise HTTPException(400, "Missing Stripe signature")

    try:
        event = stripe.Webhook.construct_event(raw_body, signature, secret, tolerance=300)
    except (ValueError, stripe.error.SignatureVerificationError):
        raise HTTPException(400, "Invalid Stripe webhook")

    # Never accept production events in this test-only receiver.
    if event.get("livemode") is not False:
        log.error("Rejected non-test event, id=%s", event.get("id"))
        raise HTTPException(400, "Wrong Stripe mode")

    event_id = event.get("id")
    event_type = event.get("type")
    if not isinstance(event_id, str) or not event_id.startswith("evt_") or not isinstance(event_type, str):
        raise HTTPException(400, "Invalid event envelope")

    # This first receiver handles v1 snapshot events. Thin v2 events require
    # separate event retrieval / verification and must not be silently treated as snapshots.
    if event_type not in EVENT_TYPES:
        return JSONResponse({"received": True, "status": "ignored"})

    obj = (event.get("data") or {}).get("object") or {}
    obj_id = obj.get("id") if isinstance(obj, dict) else getattr(obj, "id", None)
    if not isinstance(obj_id, str):
        raise HTTPException(400, "Missing Stripe resource ID")

    try:
        # A separate schema prevents mutation of the preexisting FAME ledger.
        with psycopg.connect(db_url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO fame_stripe.intake_events
                       (stripe_event_id, event_type, stripe_object_id, stripe_account_id, stripe_created, livemode)
                       VALUES (%s, %s, %s, %s, %s, false)
                       ON CONFLICT (stripe_event_id) DO NOTHING""",
                    (event_id, event_type, obj_id, event.get("account"), event.get("created")),
                )
                inserted = cur.rowcount == 1
                if inserted:
                    # Same database transaction as event intake: either both persist or neither.
                    from app.fame_stripe_event_apply import apply_verified_event
                    apply_verified_event(cur, event)
                    cur.execute("""UPDATE fame_stripe.intake_events SET processing_status='PROCESSED'
                                   WHERE stripe_event_id=%s""",(event_id,))
            conn.commit()
    except Exception:
        # Do not acknowledge events we failed to persist: Stripe will retry.
        log.exception("Failed to persist verified event %s", event_id)
        raise HTTPException(503, "Intake temporarily unavailable")

    log.info("Stripe test event intake event=%s type=%s inserted=%s", event_id, event_type, inserted)
    return {"received": True, "status": "stored" if inserted else "duplicate"}

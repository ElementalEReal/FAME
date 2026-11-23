"""LIVE-only Stripe *snapshot* event intake. No TEST imports or auto-mount.

To be mounted later explicitly in the isolated LIVE app after acceptance.
Does not initiate payouts, refunds, transfers, or fulfillment.
"""
from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from app.live_settlement import SUPPORTED, SettlementRejected, apply_live_event

log = logging.getLogger("fame.live.webhook")
router = APIRouter()


def verify_live_signature(raw_body: bytes, signature: str):
    """Use official Stripe SDK to enforce signed payload with 300s tolerance."""
    if os.getenv("FAME_LIVE_WEBHOOK_ENABLED") != "1":
        raise SettlementRejected("LIVE_WEBHOOK_DISABLED")
    secret = os.getenv("FAME_LIVE_STRIPE_WEBHOOK_SECRET", "")
    if not secret.startswith("whsec_") or len(secret) < 20:
        raise SettlementRejected("LIVE_WEBHOOK_SECRET_UNAVAILABLE")
    if not signature or not isinstance(raw_body, bytes) or not (0 < len(raw_body) <= 1024 * 1024):
        raise SettlementRejected("LIVE_WEBHOOK_REQUEST_INVALID")
    try:
        import stripe
        event = stripe.Webhook.construct_event(raw_body, signature, secret, tolerance=300)
    except Exception as exc:
        raise SettlementRejected("LIVE_WEBHOOK_SIGNATURE_INVALID") from exc
    if not isinstance(event, dict):
        try:
            event = event.to_dict_recursive()
        except Exception as exc:
            raise SettlementRejected("LIVE_WEBHOOK_EVENT_INVALID") from exc
    if event.get("livemode") is not True:
        raise SettlementRejected("LIVE_WEBHOOK_MODE_MISMATCH")
    return event


@router.post("/v1/live/stripe/webhook", include_in_schema=False)
async def live_stripe_webhook(request: Request):
    if os.getenv("FAME_LIVE_WEBHOOK_ENABLED") != "1":
        raise HTTPException(503, "LIVE_WEBHOOK_DISABLED")
    raw = await request.body()
    if len(raw) > 1024 * 1024:
        raise HTTPException(413, "LIVE_WEBHOOK_PAYLOAD_TOO_LARGE")
    try:
        event = verify_live_signature(raw, request.headers.get("stripe-signature", ""))
    except SettlementRejected:
        raise HTTPException(400, "LIVE_WEBHOOK_INVALID") from None
    if event.get("type") not in SUPPORTED:
        # Signed but unrelated event; no financial writes.
        return {"received": True, "status": "ignored"}
    try:
        # Import lazily to keep offline pure unit tests isolated from Neon.
        from app.live_db import live_database
        with live_database(read_only=False) as conn:
            with conn.cursor() as cur:
                status = apply_live_event(cur, event, raw)
        return {"received": True, "status": status}
    except Exception:
        # Intentionally no 2xx on persistence or reconciliation failure.
        # Stripe retries; investigate if this repeats.
        log.exception("FAME LIVE webhook transaction failed")
        raise HTTPException(503, "LIVE_WEBHOOK_PROCESSING_UNAVAILABLE") from None

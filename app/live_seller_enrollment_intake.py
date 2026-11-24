"""FAME LIVE pending seller enrollment intake; never grants verified seller authority.

Mount under the isolated LIVE application only after review. Disabled by default.
All received account IDs are *claims*, not evidence of ownership.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request

from app.live_db import live_database

router = APIRouter()
PATH = "/v1/live/seller/enrollment/request"
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ACCOUNT = re.compile(r"acct_[A-Za-z0-9]+\Z")
_NONCE = re.compile(r"[a-f0-9]{48}\Z")
_ALLOWED_FIELDS = {"seller_profile_id", "stripe_account_id"}


def checked_claim(body: bytes) -> tuple[str, str]:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("INVALID_REQUEST")
    if not isinstance(data, dict) or set(data) != _ALLOWED_FIELDS:
        raise ValueError("INVALID_REQUEST")
    seller, account = data["seller_profile_id"], data["stripe_account_id"]
    if not isinstance(seller, str) or not _ID.fullmatch(seller):
        raise ValueError("INVALID_SELLER_ID")
    if not isinstance(account, str) or not _ACCOUNT.fullmatch(account):
        raise ValueError("INVALID_STRIPE_ACCOUNT_ID")
    return seller, account


def verify_signed_request(body: bytes, headers: dict, secret: str, *, now: int | None = None) -> str:
    """Reuses FAME's exact HMAC envelope; nonce consumption occurs in DB transaction."""
    if len(body) > 2048 or len(secret) < 32:
        raise ValueError("INVALID_REQUEST")
    timestamp = headers.get("x-fame-timestamp", "")
    nonce = headers.get("x-fame-nonce", "")
    signature = headers.get("x-fame-signature", "")
    if not isinstance(timestamp, str) or not timestamp.isascii() or not timestamp.isdecimal() or len(timestamp) > 12:
        raise ValueError("UNAUTHORIZED")
    now = int(time.time()) if now is None else now
    if abs(now - int(timestamp)) > 300:
        raise ValueError("UNAUTHORIZED")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("UNAUTHORIZED")
    if not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{64}", signature):
        raise ValueError("UNAUTHORIZED")
    digest = hashlib.sha256(body).hexdigest()
    base = "\n".join(["POST", PATH, timestamp, nonce, digest]).encode()
    expected = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("UNAUTHORIZED")
    return nonce


def create_pending_request(seller: str, account: str, nonce: str) -> str:
    """Atomic nonce use and pending claim. Does NOT touch verified seller_accounts."""
    request_id = str(uuid4())
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            # Duplicate nonce fails inside the same transaction; never silently reuse.
            cur.execute(
                "INSERT INTO fame_live.seller_enrollment_nonces (nonce) VALUES (%s)",
                (nonce,),
            )
            cur.execute(
                "INSERT INTO fame_live.seller_enrollment_requests "
                "(request_id, seller_profile_id, claimed_stripe_account_id, status) "
                "VALUES (%s, %s, %s, 'PENDING')",
                (request_id, seller, account),
            )
    return request_id


@router.post(PATH, status_code=202)
async def seller_enrollment_request(request: Request):
    if os.getenv("FAME_LIVE_SELLER_ENROLLMENT_ENABLED") != "1":
        raise HTTPException(status_code=404, detail="NOT_FOUND")
    secret = os.getenv("FAME_LIVE_SELLER_ENROLLMENT_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="ENROLLMENT_NOT_CONFIGURED")
    body = await request.body()
    if len(body) > 2048:
        raise HTTPException(status_code=413, detail="REQUEST_TOO_LARGE")
    try:
        nonce = verify_signed_request(body, dict(request.headers), secret)
        seller, account = checked_claim(body)
    except ValueError:
        raise HTTPException(status_code=403, detail="ENROLLMENT_DENIED")
    try:
        enrollment_id = create_pending_request(seller, account, nonce)
    except Exception:
        # Avoid exposing DB conflicts, replay state, or any sensitive records.
        raise HTTPException(status_code=409, detail="ENROLLMENT_NOT_ACCEPTED")
    return {"status": "PENDING", "enrollment_id": enrollment_id,
            "ownership_verified": False, "checkout_enabled": False}

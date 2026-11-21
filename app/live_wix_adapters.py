"""FAME LIVE Wix trust adapters. NOT a checkout implementation.

A signed request must pass verify_live_bridge before the reviewer adapter runs.
Reviewer proof is separately signed, and body-bound; listing is fetched from a
protected Wix HTTP function, not sourced from the caller's JSON.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import time
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, build_opener, HTTPRedirectHandler
from app.live_catalog_governance import VerifiedListing
from app.live_policy import PurchaseRejected

_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{48}$")

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _secret(name: str) -> str:
    s = os.getenv(name, "")
    if len(s.encode("utf-8")) < 32:
        raise PurchaseRejected("LIVE_WIX_TRUST_NOT_CONFIGURED")
    return s

def _safe_member(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise PurchaseRejected("LIVE_WIX_MEMBER_INVALID")
    return value

def _proof_message(*, method, path, timestamp, nonce, body_hash, member_id):
    return "\n".join([method.upper(), path, timestamp, nonce, body_hash, member_id])

def verify_wix_reviewer_proof(request) -> str:
    """Do NOT read claimed reviewer ID from JSON here; independent header proof.

    This must execute only after the HMAC transport middleware succeeds.
    The Wix webMethod must derive the member ID from currentMember.
    """
    member = _safe_member(request.headers.get("x-fame-live-member", ""))
    proof = request.headers.get("x-fame-member-proof", "")
    ts = request.headers.get("x-fame-timestamp", "")
    nonce = request.headers.get("x-fame-nonce", "")
    if not _HEX.fullmatch(proof) or not _NONCE.fullmatch(nonce) or not re.fullmatch(r"[0-9]{10,12}", ts):
        raise PurchaseRejected("LIVE_WIX_MEMBER_PROOF_INVALID")
    if abs(time.time() - int(ts)) > 300:
        raise PurchaseRejected("LIVE_WIX_MEMBER_PROOF_EXPIRED")
    # Starlette request.body() is async; verify against signed bytes cached by
    # an explicit ASGI adapter. Never serialize request JSON a second time.
    body = getattr(request.state, "live_signed_raw_body", None)
    if not isinstance(body, bytes) or len(body) > 16384:
        raise PurchaseRejected("LIVE_SIGNED_BODY_UNAVAILABLE")
    body_hash = hashlib.sha256(body).hexdigest()
    message = _proof_message(method=request.method, path=request.url.path,
        timestamp=ts, nonce=nonce, body_hash=body_hash, member_id=member)
    expected = hmac.new(_secret("FAME_LIVE_REVIEW_PROOF_SECRET").encode(),
        message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(proof, expected):
        raise PurchaseRejected("LIVE_WIX_MEMBER_PROOF_INVALID")
    return member

def parse_verified_wix_snapshot(data: dict, listing_id: str,
                               stripe_account_id: str, seller_ready: bool) -> VerifiedListing:
    """Validate Wix-controlled fields; Stripe readiness must come from Render."""
    if not isinstance(data, dict) or type(seller_ready) is not bool:
        raise PurchaseRejected("LIVE_WIX_SNAPSHOT_INVALID")
    if data.get("listing_id") != listing_id or not _ID.fullmatch(str(listing_id)):
        raise PurchaseRejected("LIVE_WIX_LISTING_MISMATCH")
    seller = data.get("seller_profile_id")
    if not isinstance(seller, str) or not _ID.fullmatch(seller):
        raise PurchaseRejected("LIVE_WIX_SELLER_INVALID")
    fp = data.get("approval_fingerprint")
    if not isinstance(fp, str) or not _HEX.fullmatch(fp):
        raise PurchaseRejected("LIVE_WIX_FINGERPRINT_INVALID")
    amount = data.get("amount_minor")
    if type(amount) is not int or not (50 <= amount <= 10_000_000):
        raise PurchaseRejected("LIVE_WIX_AMOUNT_INVALID")
    title = data.get("title")
    if not isinstance(title, str) or not (1 <= len(title.strip()) <= 150):
        raise PurchaseRejected("LIVE_WIX_TITLE_INVALID")
    if data.get("currency") != "usd" or data.get("published_public") is not True:
        raise PurchaseRejected("LIVE_WIX_NOT_PURCHASABLE")
    return VerifiedListing(listing_id=listing_id, seller_profile_id=seller,
        seller_stripe_account_id=stripe_account_id, title=title.strip(),
        currency="usd", amount_minor=amount, approval_fingerprint=fp,
        published_public=True, seller_eligible=seller_ready)

def _snapshot_url() -> str:
    url = os.getenv("FAME_LIVE_WIX_SNAPSHOT_URL", "")
    parsed = urlsplit(url)
    # Fixed, operator-configured HTTPS URL. Never accept a caller-supplied URL.
    if parsed.scheme != "https" or not parsed.hostname or parsed.port not in (None, 443) \
            or parsed.username or parsed.password or parsed.query or parsed.fragment \
            or not parsed.path.endswith("/_functions/fameLiveSnapshot"):
        raise PurchaseRejected("LIVE_WIX_SNAPSHOT_URL_INVALID")
    return url

def fetch_wix_snapshot(listing_id: str, *, account_resolver, transport=None) -> VerifiedListing:
    """Perform independent request to authoritative Wix endpoint.

    account_resolver(seller_profile_id) MUST query a trusted LIVE Connect account
    mapping and Stripe LIVE charges/payout readiness; not the Wix response.
    """
    if not isinstance(listing_id, str) or not _ID.fullmatch(listing_id):
        raise PurchaseRejected("LIVE_LISTING_ID_INVALID")
    url = _snapshot_url()
    from secrets import token_hex
    nonce = token_hex(24)
    ts = str(int(time.time()))
    body = json.dumps({"listing_id": listing_id}, separators=(",", ":")).encode()
    path = urlsplit(url).path
    digest = hashlib.sha256(body).hexdigest()
    message = "\n".join(["POST", path, ts, nonce, digest])
    signature = hmac.new(_secret("FAME_LIVE_SNAPSHOT_SECRET").encode(),
                         message.encode(), hashlib.sha256).hexdigest()
    headers = {"Content-Type":"application/json", "x-fame-timestamp":ts,
        "x-fame-nonce":nonce, "x-fame-signature":signature}
    if transport is None:
        opener = build_opener(_NoRedirect())
        def transport(u, b, h):
            with opener.open(UrlRequest(u, data=b, headers=h, method="POST"), timeout=5) as response:
                raw = response.read(16385)
                if len(raw) > 16384 or response.status != 200:
                    raise PurchaseRejected("LIVE_WIX_SNAPSHOT_UNAVAILABLE")
                return json.loads(raw)
    try:
        data = transport(url, body, headers)
    except PurchaseRejected:
        raise
    except Exception as exc:
        raise PurchaseRejected("LIVE_WIX_SNAPSHOT_UNAVAILABLE") from exc
    if not isinstance(data, dict) or data.get("ok") is not True:
        raise PurchaseRejected("LIVE_WIX_SNAPSHOT_UNAVAILABLE")
    seller = data.get("seller_profile_id")
    if not isinstance(seller, str) or not _ID.fullmatch(seller):
        raise PurchaseRejected("LIVE_WIX_SELLER_INVALID")
    account_id, ready = account_resolver(seller)
    return parse_verified_wix_snapshot(data, listing_id, account_id, ready)

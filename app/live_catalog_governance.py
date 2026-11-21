"""FAME LIVE catalogue governance core. NOT a public endpoint.

This module cannot establish that a Wix reviewer or listing is trustworthy by itself.
Production callers MUST supply independently verified adapters for reviewer and
listing identity. All write operations are gated OFF by default. No Stripe calls.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

from app.live_db import live_database
from app.live_policy import PurchaseRejected

_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ACCT = re.compile(r"acct_[A-Za-z0-9]+\Z")


@dataclass(frozen=True)
class VerifiedListing:
    """Only the trusted listing adapter may construct/return this value."""
    listing_id: str
    seller_profile_id: str
    seller_stripe_account_id: str
    title: str
    currency: str
    amount_minor: int
    approval_fingerprint: str
    published_public: bool
    seller_eligible: bool


def _uuid4(value: str | UUID) -> UUID:
    try:
        result = UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise PurchaseRejected("LIVE_DECISION_ID_INVALID") from exc
    if result.version != 4:
        raise PurchaseRejected("LIVE_DECISION_ID_INVALID")
    return result


def _enabled():
    if os.getenv("FAME_LIVE_CATALOG_WRITES_ENABLED") != "1":
        raise PurchaseRejected("LIVE_CATALOG_WRITES_DISABLED")


def _valid(snapshot: VerifiedListing, listing_id: str) -> None:
    if type(snapshot) is not VerifiedListing:
        raise PurchaseRejected("LIVE_TRUSTED_SNAPSHOT_REQUIRED")
    if not isinstance(listing_id, str) or not _ID.fullmatch(listing_id):
        raise PurchaseRejected("LIVE_LISTING_ID_INVALID")
    if snapshot.listing_id != listing_id or not _ID.fullmatch(snapshot.seller_profile_id):
        raise PurchaseRejected("LIVE_LISTING_MISMATCH")
    if not _ACCT.fullmatch(snapshot.seller_stripe_account_id):
        raise PurchaseRejected("LIVE_SELLER_ACCOUNT_INVALID")
    if not isinstance(snapshot.title, str) or not (1 <= len(snapshot.title.strip()) <= 150):
        raise PurchaseRejected("LIVE_TITLE_INVALID")
    if snapshot.currency != "usd" or type(snapshot.amount_minor) is not int or not (50 <= snapshot.amount_minor <= 10_000_000):
        raise PurchaseRejected("LIVE_AMOUNT_INVALID")
    if not isinstance(snapshot.approval_fingerprint, str) or not _HEX.fullmatch(snapshot.approval_fingerprint):
        raise PurchaseRejected("LIVE_FINGERPRINT_INVALID")
    if not snapshot.published_public or not snapshot.seller_eligible:
        raise PurchaseRejected("LIVE_LISTING_NOT_ELIGIBLE")


def register_disabled_listing(*, listing_id: str,
                              fetch_verified_listing: Callable[[str], VerifiedListing]) -> int:
    """Register a new listing ONLY as disabled revision 1; never approve it.

    fetch_verified_listing MUST independently re-fetch Wix publication/listing data,
    verify ownership and a live Connect account mapping, and compute the
    canonical fingerprint, rather than returning client-supplied parameters.
    """
    _enabled()
    if not isinstance(listing_id, str) or not _ID.fullmatch(listing_id):
        raise PurchaseRejected("LIVE_LISTING_ID_INVALID")
    snapshot = fetch_verified_listing(listing_id)
    _valid(snapshot, listing_id)
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO fame_live.catalog
                  (listing_id,seller_profile_id,seller_stripe_account_id,title,
                   currency,amount_minor,approval_fingerprint,approval_revision,enabled)
                VALUES (%s,%s,%s,%s,%s,%s,%s,1,FALSE)
                ON CONFLICT (listing_id) DO NOTHING
                RETURNING approval_revision
            """, (snapshot.listing_id,snapshot.seller_profile_id,
                  snapshot.seller_stripe_account_id,snapshot.title.strip(),
                  snapshot.currency,snapshot.amount_minor,snapshot.approval_fingerprint))
            created = cur.fetchone()
            if created is None:
                raise PurchaseRejected("LIVE_LISTING_ALREADY_REGISTERED")
            return created[0]


def decide_live_listing(*, listing_id: str, request_id: str | UUID,
                        action: str, reason: str,
                        require_verified_reviewer: Callable[[], str],
                        fetch_verified_listing: Callable[[str], VerifiedListing]) -> int:
    """Audit an explicit APPROVE/REVOKE and advance revision atomically.

    Both injected callbacks MUST be trusted backend code: reviewer verification
    must bind a Wix SiteMember session to the independent LIVE reviewer allowlist,
    and listing verification must re-fetch current authoritative content and
    verify live seller readiness. DO NOT expose caller-supplied reviewer IDs.
    """
    _enabled()
    if os.getenv("FAME_LIVE_APPROVAL_WRITES_ENABLED") != "1":
        raise PurchaseRejected("LIVE_APPROVAL_WRITES_DISABLED")
    uid = _uuid4(request_id)
    if action not in ("APPROVE", "REVOKE"):
        raise PurchaseRejected("LIVE_ACTION_INVALID")
    if not isinstance(listing_id, str) or not _ID.fullmatch(listing_id):
        raise PurchaseRejected("LIVE_LISTING_ID_INVALID")
    if not isinstance(reason, str) or len(reason.strip()) > 500 or (action == "REVOKE" and not reason.strip()):
        raise PurchaseRejected("LIVE_REASON_INVALID")
    reviewer = require_verified_reviewer()
    if not isinstance(reviewer, str) or not _ID.fullmatch(reviewer):
        raise PurchaseRejected("LIVE_REVIEWER_INVALID")
    # A fresh, trusted snapshot is required for approval. Revocation must be
    # possible even if the listing has been deleted or seller disabled.
    snapshot = None
    if action == "APPROVE":
        snapshot = fetch_verified_listing(listing_id)
        _valid(snapshot, listing_id)
    with live_database(read_only=False) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT listing_id,seller_profile_id,seller_stripe_account_id,
                       title,currency,amount_minor,approval_fingerprint,
                       approval_revision,enabled
                FROM fame_live.catalog WHERE listing_id=%s FOR UPDATE
            """, (listing_id,))
            row = cur.fetchone()
            if row is None:
                raise PurchaseRejected("LIVE_LISTING_NOT_REGISTERED")
            cur.execute("""
                SELECT listing_id,approval_revision,reviewer_member_id,action,
                       approval_fingerprint,reason
                FROM fame_live.approval_audit WHERE request_id=%s
            """, (uid,))
            prior = cur.fetchone()
            if prior:
                if (prior[0],prior[2],prior[3],prior[5]) != (listing_id,reviewer,action,reason.strip()):
                    raise PurchaseRejected("LIVE_APPROVAL_REPLAY_CONFLICT")
                if action == "APPROVE" and prior[4] != snapshot.approval_fingerprint:
                    raise PurchaseRejected("LIVE_APPROVAL_REPLAY_CONFLICT")
                return prior[1]
            if action == "APPROVE":
                expected = (snapshot.listing_id,snapshot.seller_profile_id,
                            snapshot.seller_stripe_account_id,snapshot.title.strip(),
                            snapshot.currency,snapshot.amount_minor,
                            snapshot.approval_fingerprint)
                if row[:7] != expected:
                    raise PurchaseRejected("LIVE_CATALOG_STALE_RE_REGISTER_REQUIRED")
                if row[8]:
                    raise PurchaseRejected("LIVE_ALREADY_APPROVED")
                new_fingerprint = snapshot.approval_fingerprint
            else:
                if not row[8]:
                    raise PurchaseRejected("LIVE_ALREADY_REVOKED")
                new_fingerprint = row[6]
            revision = row[7] + 1
            cur.execute("""
                UPDATE fame_live.catalog
                   SET enabled=%s,approval_revision=%s,updated_at=now()
                 WHERE listing_id=%s AND approval_revision=%s
            """, (action == "APPROVE",revision,listing_id,row[7]))
            if cur.rowcount != 1:
                raise PurchaseRejected("LIVE_APPROVAL_CONFLICT")
            cur.execute("""
                INSERT INTO fame_live.approval_audit
                  (audit_id,request_id,listing_id,approval_revision,
                   reviewer_member_id,action,approval_fingerprint,reason)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (uid,uid,listing_id,revision,reviewer,action,
                  new_fingerprint,reason.strip()))
            return revision

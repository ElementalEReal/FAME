"""FAME LIVE: strictly read-only trusted Connect seller resolution.

This code NEVER provisions, claims, or updates a Stripe account. Account bindings
must originate through a separately audited, trusted provisioning workflow.
Never import Stripe TEST helpers or accept seller-provided account IDs.
"""
from __future__ import annotations

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.live_db import live_database
from app.live_policy import PurchaseRejected

_SELLER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ACCOUNT = re.compile(r"acct_[A-Za-z0-9]+\Z")
_STRIPE_VERSION = "2026-10-28.endive"  # Pinned to deployed FAME Accounts v2 TEST implementation.


def _account_lookup(seller_profile_id: str):
    with live_database(read_only=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT stripe_account_id, ownership_verified_at "
                "FROM fame_live.seller_accounts "
                "WHERE seller_profile_id = %s AND status = 'ACTIVE'",
                (seller_profile_id,),
            )
            return cur.fetchone()


def _stripe_get(account_id: str):
    key = os.environ.get("FAME_LIVE_STRIPE_SECRET_KEY", "")
    if not key.startswith(("sk_live_", "rk_live_")):
        raise PurchaseRejected("LIVE_STRIPE_CREDENTIAL_UNAVAILABLE")
    if os.environ.get("FAME_LIVE_STRIPE_VERIFY_ENABLED") != "1":
        raise PurchaseRejected("LIVE_STRIPE_VERIFICATION_DISABLED")
    # No attacker-controlled URL; account id is validated before call.
    from urllib.parse import urlencode
    query = urlencode([
        ("include[0]", "configuration.recipient"),
        ("include[1]", "requirements"),
    ])
    url = "https://api.stripe.com/v2/core/accounts/" + quote(account_id, safe="") + "?" + query
    req = Request(url, headers={
        "Authorization": "Bearer " + key,
        "Stripe-Version": _STRIPE_VERSION,
        "Accept": "application/json",
    }, method="GET")
    try:
        with urlopen(req, timeout=10) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise PurchaseRejected("LIVE_STRIPE_RESPONSE_INVALID")
            return json.loads(raw)
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise PurchaseRejected("LIVE_STRIPE_VERIFICATION_UNAVAILABLE") from exc


def _status_active(value):
    return isinstance(value, dict) and value.get("status") == "active"


def resolve_live_seller(seller_profile_id: str, *, lookup=None, stripe_get=None):
    """Return (account_id, ready) for validated canonical FAME seller profile.

    Callers receive (id, False) when Stripe reports a real but unready account;
    absent/invalid bindings and mismatches fail closed. No live account is
    provisioned by calling this function.
    """
    if not isinstance(seller_profile_id, str) or not _SELLER.fullmatch(seller_profile_id):
        raise PurchaseRejected("LIVE_SELLER_ID_INVALID")
    lookup = _account_lookup if lookup is None else lookup
    stripe_get = _stripe_get if stripe_get is None else stripe_get
    try:
        row = lookup(seller_profile_id)
    except PurchaseRejected:
        raise
    except Exception as exc:
        raise PurchaseRejected("LIVE_SELLER_MAPPING_UNAVAILABLE") from exc
    if not row or len(row) != 2 or row[1] is None or not isinstance(row[0], str) or not _ACCOUNT.fullmatch(row[0]):
        raise PurchaseRejected("LIVE_SELLER_NOT_VERIFIED")
    account_id = row[0]
    try:
        account = stripe_get(account_id)
    except PurchaseRejected:
        raise
    except Exception as exc:
        raise PurchaseRejected("LIVE_STRIPE_VERIFICATION_UNAVAILABLE") from exc
    if not isinstance(account, dict) or account.get("id") != account_id or account.get("livemode") is not True:
        raise PurchaseRejected("LIVE_STRIPE_ACCOUNT_MISMATCH")
    # Ownership provenance is anchored both in the audited LIVE mapping and
    # FAME-controlled metadata set during trusted account provisioning.
    metadata = account.get("metadata") or {}
    if not isinstance(metadata, dict) or metadata.get("fame_seller_key") != seller_profile_id:
        raise PurchaseRejected("LIVE_SELLER_OWNERSHIP_MISMATCH")
    # FAME is merchant of record for destination charges: the connected
    # seller needs recipient transfers, not seller-side direct card charges.
    # Accounts v2 returns null configuration fields unless explicitly included.
    applied = account.get("applied_configurations")
    if not isinstance(applied, list) or "recipient" not in applied:
        return (account_id, False)
    conf = account.get("configuration")
    if not isinstance(conf, dict):
        raise PurchaseRejected("LIVE_STRIPE_RESPONSE_INVALID")
    recipient = conf.get("recipient")
    if not isinstance(recipient, dict):
        raise PurchaseRejected("LIVE_STRIPE_RESPONSE_INVALID")
    capabilities = recipient.get("capabilities")
    if not isinstance(capabilities, dict):
        raise PurchaseRejected("LIVE_STRIPE_RESPONSE_INVALID")
    balance = capabilities.get("stripe_balance")
    if not isinstance(balance, dict):
        raise PurchaseRejected("LIVE_STRIPE_RESPONSE_INVALID")
    transfers = balance.get("stripe_transfers")
    # Ready here means eligible for destination *transfer*, NOT confirmed
    # external-bank payout readiness. Payout-method and requirements checks
    # are a separate acceptance gate before first real-money checkout.
    return (account_id, _status_active(transfers))

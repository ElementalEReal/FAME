"""Pure FAME live purchase decisions, NO Stripe side effects.

Database caller must SELECT catalog ... FOR UPDATE in the same transaction
as INSERT purchase_intents. The catalog is server-maintained, never writable
by a browser or listing owner. This is not a checkout endpoint.
"""
from __future__ import annotations
from dataclasses import dataclass
from uuid import UUID
import re

ID = re.compile(r'^[A-Za-z0-9_-]{1,128}$')
FINGERPRINT = re.compile(r'^[0-9a-f]{64}$')

class PurchaseRejected(ValueError):
    pass

@dataclass(frozen=True)
class Catalog:
    listing_id: str
    seller_profile_id: str
    seller_stripe_account_id: str
    title: str
    amount_minor: int
    currency: str
    approval_fingerprint: str
    approval_revision: int
    enabled: bool

@dataclass(frozen=True)
class Intent:
    intent_id: UUID
    listing_id: str
    buyer_profile_id: str
    seller_profile_id: str
    amount_minor: int
    approval_revision: int
    approval_fingerprint: str


def fee_cents(gross: int, basis_points: int = 500) -> int:
    if type(gross) is not int or not (50 <= gross <= 10_000_000):
        raise PurchaseRejected('AMOUNT_INVALID')
    if basis_points != 500:
        raise PurchaseRejected('FEE_POLICY_UNAPPROVED')
    return (gross * basis_points + 5000) // 10_000


def authorize(catalog: Catalog, intent: Intent) -> dict:
    if not catalog.enabled:
        raise PurchaseRejected('LISTING_NOT_LIVE_APPROVED')
    if not ID.fullmatch(catalog.listing_id) or not ID.fullmatch(catalog.seller_profile_id):
        raise PurchaseRejected('CATALOG_ID_INVALID')
    if not ID.fullmatch(intent.buyer_profile_id):
        raise PurchaseRejected('BUYER_INVALID')
    if intent.buyer_profile_id == catalog.seller_profile_id:
        raise PurchaseRejected('SELF_PURCHASE_DENIED')
    if not catalog.seller_stripe_account_id.startswith('acct_'):
        raise PurchaseRejected('SELLER_ACCOUNT_INVALID')
    if catalog.currency != 'usd':
        raise PurchaseRejected('CURRENCY_INVALID')
    if not FINGERPRINT.fullmatch(catalog.approval_fingerprint):
        raise PurchaseRejected('APPROVAL_INVALID')
    if catalog.approval_revision <= 0:
        raise PurchaseRejected('REVISION_INVALID')
    if (intent.listing_id != catalog.listing_id or
        intent.seller_profile_id != catalog.seller_profile_id or
        intent.amount_minor != catalog.amount_minor or
        intent.approval_revision != catalog.approval_revision or
        intent.approval_fingerprint != catalog.approval_fingerprint):
        raise PurchaseRejected('INTENT_CATALOG_CONFLICT')
    if not catalog.title.strip() or len(catalog.title) > 150:
        raise PurchaseRejected('TITLE_INVALID')
    fee = fee_cents(catalog.amount_minor)
    if fee >= catalog.amount_minor:
        raise PurchaseRejected('FEE_EXCEEDS_AMOUNT')
    return {
        'listing_id': catalog.listing_id,
        'buyer_profile_id': intent.buyer_profile_id,
        'seller_profile_id': catalog.seller_profile_id,
        'seller_stripe_account_id': catalog.seller_stripe_account_id,
        'title': catalog.title,
        'amount_minor': catalog.amount_minor,
        'fee_minor': fee,
        'currency': 'usd',
        'approval_revision': catalog.approval_revision,
        'approval_fingerprint': catalog.approval_fingerprint,
        'intent_id': str(intent.intent_id),
    }

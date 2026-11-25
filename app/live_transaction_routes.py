"""Authenticated FAME LIVE listing-registration and buyer Checkout entry points.

Mounted only with trusted Wix bridge; not public browser API.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.live_bridge_auth import verify_live_bridge
from app.live_catalog_governance import register_disabled_listing
from app.live_checkout_claim import claim_live_checkout
from app.live_checkout_session import create_and_bind_live_checkout
from app.live_policy import PurchaseRejected
from app.live_purchase_authority import create_purchase_intent
from app.live_reviewer_authority import require_live_reviewer
from app.live_wix_adapters import verify_wix_buyer_proof

router = APIRouter(tags=["FAME LIVE Transactions"], dependencies=[Depends(verify_live_bridge)])

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    listing_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    reviewer_member_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

class CheckoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    listing_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    intent_id: UUID

@router.post("/v1/live/catalog/register")
def register(body: RegisterRequest, request: Request):
    reviewer_adapter = getattr(request.app.state, "live_reviewer_adapter", None)
    listing_adapter = getattr(request.app.state, "live_listing_adapter", None)
    if not callable(reviewer_adapter) or not callable(listing_adapter):
        raise HTTPException(503, "LIVE_GOVERNANCE_ADAPTERS_NOT_CONFIGURED")
    try:
        verified_member = reviewer_adapter(request)
        if verified_member != body.reviewer_member_id:
            raise HTTPException(403, "LIVE_REVIEWER_IDENTITY_MISMATCH")
        require_live_reviewer(verified_member)
        revision = register_disabled_listing(listing_id=body.listing_id,
                                             fetch_verified_listing=listing_adapter)
    except PurchaseRejected as exc:
        raise HTTPException(409, str(exc)) from None
    return {"ok": True, "listing_id": body.listing_id,
            "approval_revision": revision, "enabled": False}

@router.post("/v1/live/checkout/start")
def checkout(body: CheckoutRequest, request: Request):
    listing_adapter = getattr(request.app.state, "live_listing_adapter", None)
    if not callable(listing_adapter):
        raise HTTPException(503, "LIVE_LISTING_ADAPTER_NOT_CONFIGURED")
    try:
        buyer_profile_id = verify_wix_buyer_proof(request)
        # The buyer ID is NOT taken from the HTTP body. FAME Wix backend must
        # independently resolve this ID from the authenticated Wix member.
        order = create_purchase_intent(intent_id=body.intent_id,
                                       listing_id=body.listing_id,
                                       buyer_profile_id=buyer_profile_id,
                                       fetch_verified_listing=listing_adapter)
        # Never automatically retry an existing/ambiguous payment attempt.
        if order.reused or order.state != "AUTHORIZED":
            raise HTTPException(409, "LIVE_CHECKOUT_EXISTING_INTENT_REQUIRES_REVIEW")
        claim = claim_live_checkout(order_id=order.order_id,
                                    verified_buyer_profile_id=buyer_profile_id)
        bound = create_and_bind_live_checkout(claim)
    except PurchaseRejected as exc:
        # Failure after claim may leave CREATING; manual reconciliation required.
        raise HTTPException(409, str(exc)) from None
    return {"order_id": str(bound.order_id), "checkout_url": bound.checkout_url,
            "session_id": bound.session_id, "state": bound.state}

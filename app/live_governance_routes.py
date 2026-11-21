"""FAME LIVE governance routes — fail-closed integration candidate.

Do not mount this router until trusted adapters are implemented
and independently tested.
"""

from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.live_bridge_auth import verify_live_bridge
from app.live_catalog_governance import decide_live_listing
from app.live_policy import PurchaseRejected
from app.live_reviewer_authority import require_live_reviewer


router = APIRouter(
    prefix="/v1/live/catalog",
    tags=["FAME LIVE Governance"],
)


class LiveDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    listing_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    request_id: UUID
    reviewer_member_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
    )
    action: Literal["APPROVE", "REVOKE"]
    reason: str = Field(default="", max_length=500)



def verified_reviewer_for_request(reviewer_adapter, request: Request, claimed_id: str) -> str:
    """Require independent identity attestation before allowlist verification.

    reviewer_adapter MUST authenticate the reviewer independently of the
    body-supplied member ID. A valid HMAC signature alone is not sufficient.
    Until that trusted adapter is implemented, the route stays unavailable.
    """
    if not callable(reviewer_adapter):
        raise HTTPException(503, "LIVE_REVIEWER_VERIFICATION_UNAVAILABLE")
    verified_id = reviewer_adapter(request)
    if not isinstance(verified_id, str) or verified_id != claimed_id:
        raise HTTPException(403, "LIVE_REVIEWER_IDENTITY_MISMATCH")
    return require_live_reviewer(verified_id)

@router.post(
    "/decision",
    dependencies=[Depends(verify_live_bridge)],
)
def decide_listing(body: LiveDecision, request: Request):
    # These adapters must be installed by trusted server
    # initialization code, never by an HTTP request.
    reviewer_adapter = getattr(
        request.app.state,
        "live_reviewer_adapter",
        None,
    )
    listing_adapter = getattr(
        request.app.state,
        "live_listing_adapter",
        None,
    )

    if not callable(reviewer_adapter) or not callable(listing_adapter):
        raise HTTPException(
            503,
            "LIVE_GOVERNANCE_ADAPTERS_NOT_CONFIGURED",
        )

    try:
        revision = decide_live_listing(
            listing_id=body.listing_id,
            request_id=body.request_id,
            action=body.action,
            reason=body.reason,
            require_verified_reviewer=lambda: verified_reviewer_for_request(
                reviewer_adapter, request, body.reviewer_member_id
            ),
            fetch_verified_listing=listing_adapter,
        )
    except PurchaseRejected:
        raise HTTPException(409, "LIVE_GOVERNANCE_REJECTED")

    return {
        "ok": True,
        "listing_id": body.listing_id,
        "action": body.action,
        "approval_revision": revision,
    }

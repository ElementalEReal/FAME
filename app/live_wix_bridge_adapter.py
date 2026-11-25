"""Attach Wix adapters without enabling live payments or modifying TEST routes.

Explicit configuration; call only from a LIVE-only app startup after tests.
"""
import os
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from app.live_wix_adapters import verify_wix_reviewer_proof, fetch_wix_snapshot
from app.live_policy import PurchaseRejected

def configure_wix_adapters(app, *, account_resolver):
    if os.getenv("FAME_LIVE_BRIDGE_ENABLED") != "1":
        raise RuntimeError("LIVE_BRIDGE_DISABLED")
    if not callable(account_resolver):
        raise RuntimeError("LIVE_ACCOUNT_RESOLVER_NOT_CONFIGURED")
    def reviewer(request):
        try:
            return verify_wix_reviewer_proof(request)
        except PurchaseRejected as exc:
            raise HTTPException(403, "LIVE_REVIEWER_ATTESTATION_REJECTED") from exc
    def listing(listing_id):
        return fetch_wix_snapshot(listing_id, account_resolver=account_resolver)
    app.state.live_reviewer_adapter = reviewer
    app.state.live_listing_adapter = listing
    # NOTE: the reviewer proof verifier requires the exact request.body() bytes
    # cached by ASGI middleware; install_live_body_cache below.

def install_live_body_cache(app):
    @app.middleware("http")
    async def cache_live_body(request, call_next):
        if request.url.path in (
            "/v1/live/catalog/decision",
            "/v1/live/catalog/register",
            "/v1/live/checkout/start",
        ):
            raw = await request.body()
            if len(raw) > 16384:
                return JSONResponse(status_code=413, content={"detail":"LIVE_REQUEST_TOO_LARGE"})
            request.state.live_signed_raw_body = raw
        return await call_next(request)

"""Isolated FAME LIVE application entry point."""

from fastapi import FastAPI

app = FastAPI(
    title="FAME LIVE",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "service": "fame-live"}

# FAME_SNAPSHOT_PROBE_V1
# Read-only connectivity probe; disabled by default.
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def _fame_snapshot_probe():
    url = os.environ.get("FAME_LIVE_WIX_SNAPSHOT_URL", "")
    key = os.environ.get("FAME_LIVE_SNAPSHOT_SECRET", "")

    parsed = urlsplit(url)

    if (
        parsed.scheme != "https"
        or parsed.hostname not in ("elementaleye.co", "www.elementaleye.co")
        or parsed.path != "/_functions/fameLiveSnapshot"
        or parsed.query
        or parsed.fragment
        or len(key.encode("utf-8")) < 32
    ):
        errors = []
        if not url:
            errors.append("URL_MISSING")
        elif parsed.scheme != "https":
            errors.append("URL_NOT_HTTPS")
        elif parsed.hostname not in ("elementaleye.co", "www.elementaleye.co"):
            errors.append("URL_HOST_MISMATCH")
        elif parsed.path != "/_functions/fameLiveSnapshot":
            errors.append("URL_PATH_MISMATCH")
        elif parsed.query or parsed.fragment:
            errors.append("URL_HAS_EXTRA_COMPONENTS")
        if not key:
            errors.append("SECRET_MISSING")
        elif len(key.encode("utf-8")) < 32:
            errors.append("SECRET_TOO_SHORT")
        print("FAME_PROBE CONFIG_INVALID:", ",".join(errors), flush=True)
        return

    body = json.dumps(
        {"listing_id": "fame-connectivity-probe-not-real"},
        separators=(",", ":"),
    ).encode("utf-8")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect)

    for label, valid in (
        ("INVALID_SIGNATURE", False),
        ("VALID_SIGNATURE", True),
    ):
        ts = str(int(time.time()))
        nonce = secrets.token_hex(24)
        digest = hashlib.sha256(body).hexdigest()

        message = "\n".join((
            "POST",
            "/_functions/fameLiveSnapshot",
            ts,
            nonce,
            digest,
        ))

        signature = hmac.new(
            key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest() if valid else "0" * 64

        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-fame-timestamp": ts,
                "x-fame-nonce": nonce,
                "x-fame-signature": signature,
            },
        )

        try:
            with opener.open(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
        except Exception:
            print(f"FAME_PROBE {label}: NETWORK_ERROR", flush=True)
            continue

        print(f"FAME_PROBE {label}: HTTP {status}", flush=True)


@app.on_event("startup")
async def fame_snapshot_probe_startup():
    if os.environ.get("FAME_LIVE_SNAPSHOT_PROBE_ENABLED") != "1":
        return
    await asyncio.to_thread(_fame_snapshot_probe)


from app.live_reviewer_ping import router as reviewer_ping_router
app.include_router(reviewer_ping_router)

# FAME_LIVE_GOVERNANCE_WIRING_V1
# This router is absent unless the independently controlled
# LIVE bridge is explicitly enabled.
from app.live_governance_routes import router as live_governance_router
from app.live_seller_resolver import resolve_live_seller
from app.live_wix_bridge_adapter import (
    configure_wix_adapters,
    install_live_body_cache,
)

if os.environ.get("FAME_LIVE_BRIDGE_ENABLED") == "1":
    configure_wix_adapters(
        app,
        account_resolver=resolve_live_seller,
    )
    install_live_body_cache(app)
    app.include_router(live_governance_router)
# FAME_LIVE_WEBHOOK_WIRING_V1
# Keep the provider endpoint absent unless explicitly enabled.
# Financial processing also requires the webhook signing secret.
if os.environ.get("FAME_LIVE_WEBHOOK_ENABLED") == "1":
    from app.live_stripe_webhook import router as live_stripe_webhook_router
    app.include_router(live_stripe_webhook_router)

"""FAME LIVE bridge authentication.

Verifies signed server-to-server requests.
Does NOT authorize reviewers, listings, or payments.
"""

import hashlib
import hmac
import os
import re
import time

from fastapi import HTTPException, Request

from app.live_db import live_database


NONCE_PATTERN = re.compile(r"^[a-f0-9]{48}$")
SIGNATURE_PATTERN = re.compile(r"^[a-f0-9]{64}$")


def _safe_nonce_db_failure(exc: Exception) -> dict:
    """Expose only non-sensitive diagnostics in server-side logs."""
    result = {"error_type": type(exc).__name__}
    sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if isinstance(sqlstate, str) and re.fullmatch(r"[A-Z0-9]{5}", sqlstate):
        result["sqlstate"] = sqlstate
    if isinstance(exc, RuntimeError):
        if str(exc) == "FAME_LIVE_DATABASE_URL_NOT_CONFIGURED":
            result["reason"] = "DATABASE_URL_NOT_CONFIGURED"
        elif str(exc) == "FAME_LIVE_DATABASE_URL_INVALID":
            result["reason"] = "DATABASE_URL_INVALID"
    return result


async def verify_live_bridge(request: Request) -> None:
    if os.getenv("FAME_LIVE_BRIDGE_ENABLED") != "1":
        raise HTTPException(503, "LIVE_BRIDGE_DISABLED")

    secret = os.getenv("FAME_LIVE_BRIDGE_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise HTTPException(503, "LIVE_BRIDGE_NOT_CONFIGURED")

    timestamp = request.headers.get("x-fame-timestamp", "")
    nonce = request.headers.get("x-fame-nonce", "")
    supplied = request.headers.get("x-fame-signature", "")

    if (
        not re.fullmatch(r"[0-9]{10,12}", timestamp)
        or not NONCE_PATTERN.fullmatch(nonce)
        or not SIGNATURE_PATTERN.fullmatch(supplied)
    ):
        raise HTTPException(401, "LIVE_SIGNATURE_INVALID")

    if abs(time.time() - int(timestamp)) > 300:
        raise HTTPException(401, "LIVE_SIGNATURE_EXPIRED")

    body = await request.body()
    digest = hashlib.sha256(body).hexdigest()
    message = "\n".join([
        request.method.upper(),
        request.url.path,
        timestamp,
        nonce,
        digest,
    ])
    expected = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, supplied):
        raise HTTPException(401, "LIVE_SIGNATURE_INVALID")

    # Durable replay check. Successful insert is required to continue.
    try:
        with live_database(read_only=False) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO fame_live.bridge_nonces(nonce)
                    VALUES (%s)
                    ON CONFLICT DO NOTHING
                    RETURNING nonce
                    """,
                    (nonce,),
                )
                if cur.fetchone() is None:
                    raise HTTPException(409, "LIVE_REQUEST_REPLAYED")
    except HTTPException:
        raise
    except Exception as exc:
        # Server logs only. Never print str(exc), SQL, nonce, tokens, URLs,
        # or traceback: driver messages may include sensitive details.
        print(
            "FAME_LIVE_NONCE_DB_FAILURE "
            + __import__("json").dumps(_safe_nonce_db_failure(exc), sort_keys=True),
            flush=True,
        )
        raise HTTPException(503, "LIVE_REPLAY_PROTECTION_UNAVAILABLE") from None

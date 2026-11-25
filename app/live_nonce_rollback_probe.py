"""FAME LIVE: opt-in startup test of the actual nonce INSERT, always rolled back.

No HTTP route, Stripe call, purchase intent, or transaction record. This must
never be used as a substitute for normal durable replay protection.
"""
from __future__ import annotations

import json
import os
import re
from secrets import token_hex

from app.live_db import live_database


class _InsertNotConfirmed(Exception):
    """Abort transaction without committing when INSERT returns no row."""


class _ExpectedRollback(Exception):
    """Sentinel to force rollback of the enclosing live_database transaction."""


def _emit(**fields):
    print("FAME_LIVE_NONCE_ROLLBACK_PROBE " + json.dumps(fields, sort_keys=True), flush=True)


def _safe_error(exc):
    error = {"error_type": type(exc).__name__}
    state = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if isinstance(state, str) and re.fullmatch(r"[A-Z0-9]{5}", state):
        error["sqlstate"] = state
    if isinstance(exc, RuntimeError):
        if str(exc) == "FAME_LIVE_DATABASE_URL_NOT_CONFIGURED":
            error["reason"] = "DATABASE_URL_NOT_CONFIGURED"
        elif str(exc) == "FAME_LIVE_DATABASE_URL_INVALID":
            error["reason"] = "DATABASE_URL_INVALID"
    return error


def run_live_nonce_rollback_probe() -> bool:
    """Check INSERT ... RETURNING, force rollback, then verify no row persisted."""
    if os.getenv("FAME_LIVE_NONCE_ROLLBACK_PROBE_ENABLED") != "1":
        return False
    _emit(stage="START")
    nonce = token_hex(24)  # same 48 lowercase hex format as real bridge nonces
    try:
        # The intentional sentinel exits BOTH transaction contexts with an
        # exception, so psycopg rolls back instead of committing the INSERT.
        with live_database(read_only=False) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO fame_live.bridge_nonces(nonce)
                       VALUES (%s)
                       ON CONFLICT DO NOTHING
                       RETURNING nonce""",
                    (nonce,),
                )
                row = cur.fetchone()
                if row is None or row[0] != nonce:
                    _emit(stage="FAILED", reason="INSERT_NOT_CONFIRMED")
                    raise _InsertNotConfirmed()
                raise _ExpectedRollback()
    except _InsertNotConfirmed:
        return False
    except _ExpectedRollback:
        _emit(stage="INSERT_OK_ROLLED_BACK")
    except Exception as exc:
        _emit(stage="ERROR", **_safe_error(exc))
        return False

    try:
        with live_database(read_only=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM fame_live.bridge_nonces WHERE nonce = %s LIMIT 1",
                    (nonce,),
                )
                persisted = cur.fetchone() is not None
        if persisted:
            _emit(stage="FAILED", reason="ROW_PERSISTED_UNEXPECTEDLY")
            return False
        _emit(stage="PASS", insert_succeeded=True, rollback_verified=True)
        return True
    except Exception as exc:
        _emit(stage="VERIFY_ERROR", **_safe_error(exc))
        return False

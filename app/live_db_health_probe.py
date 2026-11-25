"""FAME LIVE read-only startup database diagnostic.

Opt-in via FAME_LIVE_DB_HEALTH_PROBE_ENABLED=1. No public route, Stripe
call, INSERT, checkout intent creation, or sensitive data is logged.
"""
from __future__ import annotations

import json
import os

from app.live_db import live_database


def _emit(**fields):
    print("FAME_LIVE_DB_HEALTH " + json.dumps(fields, sort_keys=True), flush=True)


def _safe_error(exc: Exception) -> dict:
    # Report a Python exception class and PostgreSQL SQLSTATE only.
    # Never log str(exc), SQL, database URLs, or query parameters.
    state = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    result = {"error_type": type(exc).__name__}
    if isinstance(state, str) and len(state) == 5 and state.isalnum():
        result["sqlstate"] = state
    if isinstance(exc, RuntimeError) and str(exc) == "FAME_LIVE_DATABASE_URL_NOT_CONFIGURED":
        result["reason"] = "DATABASE_URL_NOT_CONFIGURED"
    return result


def run_live_db_health_probe() -> bool:
    if os.getenv("FAME_LIVE_DB_HEALTH_PROBE_ENABLED") != "1":
        return False
    _emit(stage="START")
    try:
        # Check via the same write-capable connection mode as nonce insertion.
        # SQL statements are SELECT-only; never actually insert a nonce.
        with live_database(read_only=False) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        current_database() = 'neondb',
                        current_user = session_user,
                        to_regclass('fame_live.bridge_nonces') IS NOT NULL,
                        has_schema_privilege(current_user, 'fame_live', 'USAGE'),
                        has_table_privilege(current_user, 'fame_live.bridge_nonces', 'INSERT'),
                        pg_is_in_recovery()
                """)
                row = cur.fetchone()
                if row is None or len(row) != 6:
                    _emit(stage="FAILED", reason="UNEXPECTED_DB_RESULT")
                    return False
                db_is_neondb, role_is_session_user, table_exists, schema_usage, can_insert, is_replica = row
                # Do not log database hostname, user, or credentials.
                _emit(
                    stage="RESULT",
                    database_expected=bool(db_is_neondb),
                    role_session_match=bool(role_is_session_user),
                    nonce_table_exists=bool(table_exists),
                    nonce_schema_usage=bool(schema_usage),
                    nonce_insert_privilege=bool(can_insert),
                    connection_is_replica=bool(is_replica),
                )
                ready = bool(table_exists and schema_usage and can_insert and not is_replica)
                _emit(stage="PASS" if ready else "CHECK_REQUIRED")
                return ready
    except Exception as exc:
        _emit(stage="ERROR", **_safe_error(exc))
        return False

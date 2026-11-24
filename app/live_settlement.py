"""FAME LIVE verified Stripe event application; never callable from an unverified client.

All DB operations happen inside the caller's ONE transaction. Journals are
provisional operational clearing, NOT final settlement / payout confirmation.
"""
from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

SUPPORTED = frozenset({"checkout.session.completed", "checkout.session.async_payment_succeeded",
                       "checkout.session.async_payment_failed", "charge.refunded"})


class SettlementRejected(ValueError):
    pass


def _uuid(value):
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError) as e:
        raise SettlementRejected("LIVE_EVENT_ORDER_INVALID") from e


def event_facts(event: dict):
    """Parse only Stripe-signed, LIVE *snapshot* events; no thin event support."""
    if not isinstance(event, dict) or event.get("livemode") is not True:
        raise SettlementRejected("LIVE_EVENT_MODE_INVALID")
    eid = event.get("id")
    kind = event.get("type")
    if not isinstance(eid, str) or not eid.startswith("evt_") or len(eid) > 255:
        raise SettlementRejected("LIVE_EVENT_ID_INVALID")
    if kind not in SUPPORTED:
        raise SettlementRejected("LIVE_EVENT_UNSUPPORTED")
    if event.get("account") is not None:
        raise SettlementRejected("LIVE_CONNECT_SCOPED_EVENT_NOT_SUPPORTED")
    data = event.get("data")
    obj = data.get("object") if isinstance(data, dict) else None
    if not isinstance(obj, dict):
        raise SettlementRejected("LIVE_EVENT_SNAPSHOT_REQUIRED")
    if kind.startswith("checkout.session."):
        metadata = obj.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("fame_order_id"):
            raise SettlementRejected("LIVE_EVENT_ORDER_INVALID")
        order_id = _uuid(metadata["fame_order_id"])
        session_id = obj.get("id")
        pi = obj.get("payment_intent")
        amount = obj.get("amount_total")
        expected_payment_status = ("unpaid" if kind == "checkout.session.async_payment_failed"
                                   else "paid")
        if (not isinstance(session_id, str) or not session_id.startswith("cs_live_")
                or not isinstance(pi, str) or not pi.startswith("pi_")
                or type(amount) is not int or amount < 50 or obj.get("currency") != "usd"
                or obj.get("payment_status") != expected_payment_status):
            raise SettlementRejected("LIVE_PAYMENT_EVIDENCE_INVALID")
        return {"kind": ("FAILED" if kind == "checkout.session.async_payment_failed"
                         else "PAID"), "event_id": eid, "type": kind, "order_id": order_id,
                "session_id": session_id, "pi": pi, "amount": amount}
    pi = obj.get("payment_intent")
    amount_refunded = obj.get("amount_refunded")
    if (not isinstance(pi, str) or not pi.startswith("pi_")
            or type(amount_refunded) is not int or amount_refunded < 0
            or obj.get("currency") != "usd" or not str(obj.get("id", "")).startswith("ch_")):
        raise SettlementRejected("LIVE_REFUND_EVIDENCE_INVALID")
    return {"kind": "REFUND", "event_id": eid, "type": kind,
            "pi": pi, "refunded_minor": amount_refunded}


def _journal(cur, order_id, event_id, kind, lines):
    """Insert balanced operational clearing entries, checked again at DB commit."""
    debit = sum(debit for _, debit, _ in lines)
    credit = sum(credit for _, _, credit in lines)
    if debit <= 0 or debit != credit:
        raise SettlementRejected("LIVE_JOURNAL_UNBALANCED")
    jid = uuid4()
    cur.execute("""
        INSERT INTO fame_live.payment_journals
          (journal_id,order_id,provider_event_id,journal_kind,currency)
        VALUES (%s,%s,%s,%s,'usd')
    """, (jid, order_id, event_id, kind))
    for i, (account, dr, cr) in enumerate(lines, 1):
        cur.execute("""
            INSERT INTO fame_live.payment_journal_lines
              (journal_id,line_number,account_code,debit_minor,credit_minor)
            VALUES (%s,%s,%s,%s,%s)
        """, (jid, i, account, dr, cr))


def apply_live_event(cur, event: dict, raw_body: bytes):
    """Apply once inside caller-owned transaction after Stripe signature verification.

    Exactly-once per event, plus state-based replay handling across distinct events.
    Raise -> caller rolls back and returns HTTP 503 to allow Stripe retry.
    """
    if not isinstance(raw_body, bytes) or not raw_body:
        raise SettlementRejected("LIVE_RAW_EVENT_REQUIRED")
    facts = event_facts(event)
    digest = hashlib.sha256(raw_body).hexdigest()
    event_id = facts["event_id"]
    cur.execute("SELECT event_hash FROM fame_live.provider_events WHERE provider_event_id=%s", (event_id,))
    existing = cur.fetchone()
    if existing:
        if existing[0] != digest:
            raise SettlementRejected("LIVE_EVENT_REPLAY_CONFLICT")
        return "duplicate"

    if facts["kind"] in ("PAID", "FAILED"):
        cur.execute("""
            SELECT order_id, state, stripe_session_id, stripe_payment_intent_id,
                   amount_minor, fee_minor, currency
            FROM fame_live.purchase_intents
            WHERE order_id=%s FOR UPDATE
        """, (facts["order_id"],))
        row = cur.fetchone()
        if row is None:
            raise SettlementRejected("LIVE_ORDER_NOT_FOUND")
        oid, state, sid, prior_pi, amount, fee, currency = row
        if (sid != facts["session_id"] or amount != facts["amount"] or currency != "usd"
                or (prior_pi is not None and prior_pi != facts["pi"])):
            raise SettlementRejected("LIVE_PAYMENT_ORDER_MISMATCH")
        if facts["kind"] == "FAILED":
            if state == "PENDING":
                # No payment-clearing journal for a failed collection. Bind the
                # PaymentIntent to prevent a different PI from later matching.
                cur.execute("""
                    UPDATE fame_live.purchase_intents SET state='FAILED',
                        stripe_payment_intent_id=%s,updated_at=now()
                    WHERE order_id=%s AND state='PENDING'
                """, (facts["pi"], oid))
                if cur.rowcount != 1:
                    raise SettlementRejected("LIVE_FAILURE_STATE_CONFLICT")
            elif state == "FAILED":
                if prior_pi != facts["pi"]:
                    raise SettlementRejected("LIVE_PAYMENT_INTENT_MISMATCH")
            elif state in ("PAID", "PARTIALLY_REFUNDED", "REFUNDED"):
                if prior_pi != facts["pi"]:
                    raise SettlementRejected("LIVE_PAYMENT_INTENT_MISMATCH")
                # Late/out-of-order failure signal: never downgrade a paid order.
                # Preserve the signed event for reconciliation/investigation.
            else:
                raise SettlementRejected("LIVE_FAILURE_STATE_INVALID")
        elif state == "PENDING":
            cur.execute("""
                UPDATE fame_live.purchase_intents SET state='PAID',
                    stripe_payment_intent_id=%s,updated_at=now()
                WHERE order_id=%s AND state='PENDING'
            """, (facts["pi"], oid))
            if cur.rowcount != 1:
                raise SettlementRejected("LIVE_PAYMENT_STATE_CONFLICT")
            # These are provisional CLEARING entries, not proof of actual
            # settlement, platform revenue recognition or seller transfer.
            _journal(cur, oid, event_id, "PAYMENT_CLEARING", [
                ("STRIPE_PAYMENT_CLEARING", amount, 0),
                ("SELLER_TRANSFER_PENDING", 0, amount - fee),
                ("PLATFORM_FEE_PENDING", 0, fee),
            ])
        elif state in ("PAID", "PARTIALLY_REFUNDED", "REFUNDED"):
            if prior_pi != facts["pi"]:
                raise SettlementRejected("LIVE_PAYMENT_INTENT_MISMATCH")
        else:
            raise SettlementRejected("LIVE_PAYMENT_STATE_INVALID")
        order_id = oid
    else:
        cur.execute("""
            SELECT order_id,state,amount_minor,refunded_minor
            FROM fame_live.purchase_intents
            WHERE stripe_payment_intent_id=%s FOR UPDATE
        """, (facts["pi"],))
        row = cur.fetchone()
        if row is None:
            # Keep signed but not-yet-order-bound events for Stripe retry,
            # not silently accepted or misassociated.
            raise SettlementRejected("LIVE_REFUND_ORDER_NOT_FOUND")
        oid, state, gross, previous = row
        cumulative = facts["refunded_minor"]
        if cumulative > gross or previous < 0:
            raise SettlementRejected("LIVE_REFUND_AMOUNT_INVALID")
        if state not in ("PAID", "PARTIALLY_REFUNDED", "REFUNDED"):
            raise SettlementRejected("LIVE_REFUND_STATE_INVALID")
        if cumulative > previous:
            delta = cumulative - previous
            next_state = "REFUNDED" if cumulative == gross else "PARTIALLY_REFUNDED"
            cur.execute("""
                UPDATE fame_live.purchase_intents SET refunded_minor=%s,state=%s,
                   updated_at=now() WHERE order_id=%s
            """, (cumulative, next_state, oid))
            # Do NOT presume Stripe reverses seller transfer or platform fees.
            _journal(cur, oid, event_id, "REFUND_CLEARING", [
                ("REFUND_RECONCILIATION_PENDING", delta, 0),
                ("STRIPE_PAYMENT_CLEARING", 0, delta),
            ])
        order_id = oid

    cur.execute("""
        INSERT INTO fame_live.provider_events
          (provider_event_id,order_id,event_type,event_hash)
        VALUES (%s,%s,%s,%s)
    """, (event_id, order_id, facts["type"], digest))
    return "applied"

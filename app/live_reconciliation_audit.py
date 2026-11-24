"""FAME F1 read-only, fail-closed comparison of order and Stripe charge evidence.

This module NEVER authorizes payment, writes to a database, calls Stripe,
creates or reverses transfers, or marks an order reconciled. Callers must
retrieve evidence independently with platform-authorized credentials and
preserve its source IDs. All integer amounts are USD cents.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str


@dataclass(frozen=True)
class AuditResult:
    status: str  # BLOCKED, REVIEW, or EVIDENCE_MATCHED (NOT final settlement)
    findings: tuple[Finding, ...]
    charge_id: str | None = None
    balance_transaction_id: str | None = None
    transfer_id: str | None = None


def _integer(value):
    return type(value) is int and value >= 0


def _id(value, prefix):
    return type(value) is str and value.startswith(prefix) and len(value) > len(prefix)


def _evidence_id(value):
    return value if type(value) is str else None


def audit_payment_evidence(order: dict, charge: dict, balance_transaction: dict | None = None,
                           transfer: dict | None = None, *, refunded_minor: int | None = None,
                           transfer_reversed_minor: int | None = None) -> AuditResult:
    """Reconcile an EXISTING paid order with provider evidence; never silently assume missing data.

    order: {order_id, payment_intent_id, seller_account_id, amount_minor, fee_minor,
            currency, state, refunded_minor}
    charge: Stripe charge snapshot including payment_intent, paid, captured,
            amount, currency, transfer, application_fee_amount, amount_refunded.
    balance_transaction: Stripe platform charge balance transaction with fee/net.
    transfer: Stripe transfer snapshot with amount, destination, currency.

    Explicit `refunded_minor` / `transfer_reversed_minor` are verified provider totals
    supplied by the caller; missing reversal evidence is deliberately REVIEW for refunds.
    """
    blocked: list[Finding] = []
    review: list[Finding] = []
    def b(code, message): blocked.append(Finding(code, message))
    def r(code, message): review.append(Finding(code, message))

    if not isinstance(order, dict) or not isinstance(charge, dict):
        return AuditResult("BLOCKED", (Finding("INVALID_INPUT", "Order and charge must be objects"),))
    amount, fee = order.get("amount_minor"), order.get("fee_minor")
    expected_refund = order.get("refunded_minor", 0)
    if (not _integer(amount) or amount < 50 or not _integer(fee) or fee >= amount
            or not _integer(expected_refund) or expected_refund > amount
            or order.get("currency") != "usd"
            or not _id(order.get("payment_intent_id"), "pi_")
            or not _id(order.get("seller_account_id"), "acct_")
            or order.get("state") not in {"PAID", "PARTIALLY_REFUNDED", "REFUNDED"}):
        return AuditResult("BLOCKED", (Finding("INVALID_ORDER", "Order identity or amounts invalid"),))
    if (order["state"] == "PAID" and expected_refund != 0) or (order["state"] == "REFUNDED" and expected_refund != amount) or (order["state"] == "PARTIALLY_REFUNDED" and not 0 < expected_refund < amount):
        b("ORDER_REFUND_STATE_MISMATCH", "Order refund state differs from recorded amount")
    charge_id = _evidence_id(charge.get("id"))
    if charge.get("livemode") is not True or not _id(charge_id, "ch_"):
        b("CHARGE_NOT_LIVE", "Expected platform LIVE charge evidence")
    if charge.get("payment_intent") != order["payment_intent_id"]:
        b("PAYMENT_INTENT_MISMATCH", "Stripe charge belongs to a different payment intent")
    if charge.get("paid") is not True or charge.get("captured") is not True or charge.get("status") != "succeeded":
        b("CHARGE_NOT_CAPTURED", "Charge not confirmed successful and captured")
    if charge.get("currency") != "usd" or charge.get("amount") != amount:
        b("CHARGE_AMOUNT_MISMATCH", "Provider charge currency or amount mismatch")
    if charge.get("application_fee_amount") != fee:
        b("APPLICATION_FEE_MISMATCH", "Charge fee does not match FAME approved fee")
    provider_refund = refunded_minor if refunded_minor is not None else charge.get("amount_refunded")
    if not _integer(provider_refund) or provider_refund > amount:
        b("INVALID_PROVIDER_REFUND", "Provider cumulative refund invalid")
    elif provider_refund != expected_refund:
        b("REFUND_MISMATCH", "Provider cumulative refund differs from FAME")

    transfer_id = _evidence_id(charge.get("transfer"))
    if not _id(transfer_id, "tr_"):
        r("TRANSFER_NOT_LINKED", "Charge has no linked transfer evidence")
    if not isinstance(transfer, dict):
        r("TRANSFER_EVIDENCE_MISSING", "Fetch destination transfer and reversal evidence")
    else:
        if transfer.get("livemode") is not True or transfer.get("id") != transfer_id or transfer.get("currency") != "usd":
            b("TRANSFER_IDENTITY_MISMATCH", "Transfer identity, environment, or currency mismatch")
        if transfer.get("destination") != order["seller_account_id"]:
            b("TRANSFER_DESTINATION_MISMATCH", "Transfer destination does not match verified seller")
        # Destination charges generally transfer gross; app fee is separately returned
        # to platform. Do NOT assume the transfer itself equals seller's net share.
        if transfer.get("amount") != amount:
            b("TRANSFER_GROSS_MISMATCH", "Destination transfer gross differs from charge")
    txn_id = _evidence_id(charge.get("balance_transaction"))
    if not _id(txn_id, "txn_"):
        r("BALANCE_TRANSACTION_NOT_LINKED", "No linked platform balance transaction")
    if not isinstance(balance_transaction, dict):
        r("PROCESSOR_FEE_UNVERIFIED", "Stripe balance transaction required for actual fee")
    else:
        if (balance_transaction.get("id") != txn_id or balance_transaction.get("currency") != "usd"
                or balance_transaction.get("source") != charge_id
                or balance_transaction.get("amount") != amount):
            b("BALANCE_TRANSACTION_MISMATCH", "Balance transaction does not match charge")
        pf, net = balance_transaction.get("fee"), balance_transaction.get("net")
        if not _integer(pf) or type(net) is not int or net != amount - pf:
            b("PROCESSOR_FEE_INVALID", "Cannot verify real Stripe processing fee")
    if expected_refund:
        if transfer_reversed_minor is None:
            r("REFUND_TRANSFER_RECOVERY_UNVERIFIED", "Check transfer reversal/fee refund and connected balance")
        elif not _integer(transfer_reversed_minor) or transfer_reversed_minor > amount:
            b("TRANSFER_REVERSAL_INVALID", "Invalid provider transfer reversal total")
        # A reported reversal amount alone does not prove fee refund or bank settlement.
        r("REFUND_FEE_RECOVERY_UNVERIFIED", "Application fee refunds and dispute effects require separate evidence")
    if blocked:
        return AuditResult("BLOCKED", tuple(blocked + review), charge_id, txn_id, transfer_id)
    if review:
        return AuditResult("REVIEW", tuple(review), charge_id, txn_id, transfer_id)
    return AuditResult("EVIDENCE_MATCHED", (), charge_id, txn_id, transfer_id)

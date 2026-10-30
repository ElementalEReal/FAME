"""Pure TEST synthetic provider-to-ledger accounting rules; never represent bank cash."""
from __future__ import annotations

from app.core import InvalidJournal


def validate_payment(gross: int, fee: int) -> None:
    if type(gross) is not int or not (1 <= gross <= 10_000_000):
        raise InvalidJournal('PROVIDER_GROSS_INVALID')
    if type(fee) is not int or not (0 <= fee < gross):
        raise InvalidJournal('PROVIDER_FEE_INVALID')


def paid_lines(gross: int, fee: int) -> list[dict]:
    """Synthetic sale allocation, NOT settlement/bank cash or seller payouts."""
    validate_payment(gross, fee)
    rows = [
        dict(account_code='TEST_ORDER_GROSS', debit_minor=gross, credit_minor=0),
        dict(account_code='TEST_PARTICIPANT_DUE', debit_minor=0, credit_minor=gross - fee),
    ]
    if fee:
        rows.append(dict(account_code='TEST_PLATFORM_FEE', debit_minor=0, credit_minor=fee))
    return rows


def fee_refunded_cumulative(gross: int, fee: int, refunded: int) -> int:
    validate_payment(gross, fee)
    if type(refunded) is not int or not (0 <= refunded <= gross):
        raise InvalidJournal('PROVIDER_REFUND_INVALID')
    # Nominal, proportional allocation for TEST only. NOT Stripe application fee refund evidence.
    return fee * refunded // gross


def refund_delta_lines(gross: int, fee: int, previous: int, current: int) -> list[dict]:
    if not (type(previous) is int and 0 <= previous < current <= gross):
        raise InvalidJournal('PROVIDER_REFUND_WATERMARK_INVALID')
    fee_delta = fee_refunded_cumulative(gross, fee, current) - fee_refunded_cumulative(gross, fee, previous)
    delta = current - previous
    rows = [dict(account_code='TEST_ORDER_GROSS', debit_minor=0, credit_minor=delta)]
    if delta > fee_delta:
        rows.append(dict(account_code='TEST_PARTICIPANT_DUE', debit_minor=delta - fee_delta, credit_minor=0))
    if fee_delta:
        rows.append(dict(account_code='TEST_PLATFORM_FEE', debit_minor=fee_delta, credit_minor=0))
    return rows

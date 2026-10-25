"""Pure, testable synthetic ledger rules. No payment-execution code."""
from __future__ import annotations
import hashlib
import hmac
import json
import re
from typing import Any

MAX_MINOR = 10**12
IDENTIFIER = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$')
ACCOUNT = re.compile(r'^[A-Z][A-Z0-9_]{2,39}$')

class InvalidJournal(ValueError):
    pass

def identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise InvalidJournal(f'{label}_INVALID')
    return value

def normalize_lines(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not (2 <= len(raw) <= 100):
        raise InvalidJournal('JOURNAL_LINE_COUNT_INVALID')
    result = []
    debit_total = credit_total = 0
    for line in raw:
        if not isinstance(line, dict) or set(line) != {'account_code', 'debit_minor', 'credit_minor'}:
            raise InvalidJournal('JOURNAL_LINE_FIELDS_INVALID')
        account = line['account_code']
        debit, credit = line['debit_minor'], line['credit_minor']
        if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
            raise InvalidJournal('ACCOUNT_CODE_INVALID')
        if type(debit) is not int or type(credit) is not int:
            raise InvalidJournal('AMOUNT_MUST_BE_INTEGER_MINOR_UNITS')
        if debit < 0 or credit < 0 or debit > MAX_MINOR or credit > MAX_MINOR:
            raise InvalidJournal('AMOUNT_OUT_OF_RANGE')
        if (debit == 0) == (credit == 0):
            raise InvalidJournal('EXACTLY_ONE_DEBIT_OR_CREDIT_REQUIRED')
        debit_total += debit
        credit_total += credit
        result.append({'account_code': account, 'debit_minor': debit, 'credit_minor': credit})
    if debit_total != credit_total:
        raise InvalidJournal('JOURNAL_NOT_BALANCED')
    if debit_total <= 0 or debit_total > MAX_MINOR:
        raise InvalidJournal('JOURNAL_TOTAL_OUT_OF_RANGE')
    return result

def request_fingerprint(payload: dict[str, Any]) -> str:
    stable = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(stable.encode('utf8')).hexdigest()

def reversal_lines(lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(account_code=x['account_code'], debit_minor=x['credit_minor'], credit_minor=x['debit_minor']) for x in lines]

def signature(secret: str, method: str, path_and_query: str, timestamp: str, nonce: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    signed = '\n'.join((method.upper(), path_and_query, timestamp, nonce, digest)).encode('utf8')
    return hmac.new(secret.encode('utf8'), signed, hashlib.sha256).hexdigest()

def signature_ok(secret: str, supplied: str, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bool:
    return isinstance(supplied, str) and hmac.compare_digest(signature(secret, method, path, timestamp, nonce, body), supplied)

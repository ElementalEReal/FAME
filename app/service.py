"""Atomic, synthetic-only posting and reversal service. SQL database is authority."""
from __future__ import annotations
from uuid import UUID
from psycopg import errors
from .core import InvalidJournal, normalize_lines, request_fingerprint, reversal_lines


def require_grant(conn, *, tenant_id: str, project_id: str, actor_id: str, permission: str) -> None:
    row = conn.execute('''
      SELECT 1 FROM fame_finance.actor_grants
      WHERE tenant_id=%s AND project_id=%s AND actor_id=%s
        AND permission=%s AND active=true
    ''', (tenant_id, project_id, actor_id, permission)).fetchone()
    if not row:
        raise PermissionError('FAME_PROJECT_PERMISSION_DENIED')


def _fetch_receipt(conn, tenant: str, project: str, key: str, expected_hash: str):
    row = conn.execute('''
      SELECT journal_id::text, commit_receipt::text, request_hash, journal_kind,
             posting_status, reverses_journal_id::text
      FROM fame_finance.journals
      WHERE tenant_id=%s AND project_id=%s AND idempotency_key=%s
    ''', (tenant, project, key)).fetchone()
    if not row:
        raise RuntimeError('IDEMPOTENCY_CONFLICT_WITHOUT_VISIBLE_ROW')
    if row[2] != expected_hash:
        raise InvalidJournal('IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_PAYLOAD')
    return _response(row, replay=True)


def _response(row, replay: bool) -> dict:
    return {'journalId': row[0], 'commitReceipt': row[1], 'journalKind': row[3],
            'postingStatus': row[4], 'reversesJournalId': row[5],
            'idempotentReplay': replay, 'realMoneyEnabled': False}


def _persist(conn, *, tenant: str, project: str, actor: str, key: str, currency: str,
             lines: list[dict], kind: str, reverses_id: str | None, fingerprint: str):
    # The UNIQUE index (tenant, project, idempotency_key) arbitrates concurrent writers.
    # ON CONFLICT DO NOTHING waits for concurrent commit, then returns zero rows to loser.
    row = conn.execute('''
        INSERT INTO fame_finance.journals
          (tenant_id, project_id, created_by_actor, idempotency_key, request_hash,
           currency_code, journal_kind, reverses_journal_id, posting_status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'POSTED_TEST')
        ON CONFLICT (tenant_id, project_id, idempotency_key) DO NOTHING
        RETURNING journal_id::text, commit_receipt::text, request_hash,
                  journal_kind, posting_status, reverses_journal_id::text
    ''', (tenant, project, actor, key, fingerprint, currency, kind, reverses_id)).fetchone()
    if row is None:
        return _fetch_receipt(conn, tenant, project, key, fingerprint)
    journal_id = row[0]
    for i, line in enumerate(lines, start=1):
        conn.execute('''
            INSERT INTO fame_finance.journal_lines
              (journal_id, line_number, account_code, debit_minor, credit_minor)
            VALUES (%s,%s,%s,%s,%s)
        ''', (journal_id, i, line['account_code'], line['debit_minor'], line['credit_minor']))
    # In the same DB transaction, emit a durable event for future Wix projection.
    # In the same DB transaction, emit a durable event for future Wix projection.
    conn.execute('''
    INSERT INTO fame_finance.outbox_events
        (journal_id, event_type, payload)
    VALUES (
        %s::uuid,
        'TEST_JOURNAL_POSTED',
        jsonb_build_object(
            'journalId', %s::text,
            'projectId', %s::text
        )
    )
''', (journal_id, journal_id, project))
    # Balance, line-count and same-tx insert are also checked in PostgreSQL triggers.
    return _response(row, replay=False)


def create_test_journal(conn, data: dict) -> dict:
    tenant, project, actor, key = (data[k] for k in ('tenantId','projectId','actorId','idempotencyKey'))
    require_grant(conn, tenant_id=tenant, project_id=project, actor_id=actor, permission='POST_TEST')
    lines = normalize_lines(data['lines'])
    payload = {'tenantId':tenant, 'projectId':project, 'actorId':actor,
               'idempotencyKey':key, 'currencyCode': data['currencyCode'], 'lines': lines,
               'journalKind':'ORIGINAL'}
    return _persist(conn, tenant=tenant, project=project, actor=actor, key=key,
                    currency=data['currencyCode'], lines=lines, kind='ORIGINAL',
                    reverses_id=None, fingerprint=request_fingerprint(payload))


def reverse_test_journal(conn, data: dict) -> dict:
    tenant, project, actor, key = (data[k] for k in ('tenantId','projectId','actorId','idempotencyKey'))
    require_grant(conn, tenant_id=tenant, project_id=project, actor_id=actor, permission='REVERSE_TEST')
    try:
        UUID(data['originalJournalId'])
    except (ValueError, TypeError, AttributeError):
        raise InvalidJournal('ORIGINAL_JOURNAL_ID_INVALID')
    original = conn.execute('''
        SELECT journal_id::text, currency_code, journal_kind, posting_status
        FROM fame_finance.journals
        WHERE journal_id=%s AND tenant_id=%s AND project_id=%s
    ''', (data['originalJournalId'], tenant, project)).fetchone()
    if not original or original[2] != 'ORIGINAL' or original[3] != 'POSTED_TEST':
        raise InvalidJournal('ORIGINAL_TEST_JOURNAL_NOT_FOUND')
    rows = conn.execute('''
        SELECT account_code, debit_minor, credit_minor
        FROM fame_finance.journal_lines WHERE journal_id=%s ORDER BY line_number
    ''', (original[0],)).fetchall()
    lines = reversal_lines([{'account_code':x[0], 'debit_minor':x[1], 'credit_minor':x[2]} for x in rows])
    payload = {'tenantId': tenant, 'projectId': project, 'actorId': actor,
               'idempotencyKey': key, 'currencyCode': original[1], 'journalKind': 'REVERSAL',
               'originalJournalId': original[0]}
    try:
        return _persist(conn, tenant=tenant, project=project, actor=actor, key=key,
                        currency=original[1], lines=lines, kind='REVERSAL',
                        reverses_id=original[0], fingerprint=request_fingerprint(payload))
    except errors.UniqueViolation:
        # Reversal uniqueness conflicts with a different request key.
        raise InvalidJournal('ORIGINAL_ALREADY_REVERSED')


def get_test_journal(conn, *, tenant: str, project: str, actor: str, journal_id: str):
    require_grant(conn, tenant_id=tenant, project_id=project, actor_id=actor, permission='READ_TEST')
    row = conn.execute('''
        SELECT journal_id::text, commit_receipt::text, journal_kind, posting_status,
               reverses_journal_id::text, currency_code
        FROM fame_finance.journals WHERE tenant_id=%s AND project_id=%s AND journal_id=%s
    ''', (tenant, project, journal_id)).fetchone()
    if not row:
        return None
    lines = conn.execute('''
        SELECT line_number, account_code, debit_minor, credit_minor
        FROM fame_finance.journal_lines WHERE journal_id=%s ORDER BY line_number
    ''', (journal_id,)).fetchall()
    return {'journalId':row[0], 'commitReceipt':row[1], 'journalKind':row[2],
            'postingStatus':row[3], 'reversesJournalId':row[4], 'currencyCode':row[5],
            'lines':[{'lineNumber':x[0], 'accountCode':x[1], 'debitMinor':x[2], 'creditMinor':x[3]} for x in lines],
            'realMoneyEnabled':False}

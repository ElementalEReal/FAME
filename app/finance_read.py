"""FAME F1F.1: signed, READ_TEST-granted, project-scoped synthetic ledger views.

Requires existing app.main.verify_hmac and app.main.consume_nonce.
Does not create payments, modify journals, or expose a public browser API.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Query
from .core import identifier, InvalidJournal
from .db import database
from .service import require_grant


def register_finance_read_routes(app, verify_hmac, consume_nonce):
    """Register endpoints without importing app.main (avoids circular imports)."""

    @app.get('/v1/projects/{project_id}/ledger/summary')
    async def ledger_summary(
        project_id: str,
        tenantId: str,
        actorId: str,
        limit: int = Query(default=25, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
        auth=Depends(verify_hmac),
    ):
        try:
            identifier(project_id, 'PROJECT_ID')
            identifier(tenantId, 'TENANT_ID')
            identifier(actorId, 'ACTOR_ID')
        except InvalidJournal:
            raise HTTPException(422, 'INVALID_QUERY_IDENTIFIER')

        try:
            with database() as conn:
                # Consume the signed request nonce in the SAME transaction as the read.
                # This is deliberately not a DB read-only transaction: replay protection
                # requires inserting a nonce, but it never mutates journal data.
                consume_nonce(conn, auth['nonce'])
                require_grant(
                    conn,
                    tenant_id=tenantId,
                    project_id=project_id,
                    actor_id=actorId,
                    permission='READ_TEST',
                )
                # Aggregate journal headers, not lines: avoids debit+credit double-counting.
                totals = conn.execute('''
                    SELECT COUNT(*)::bigint,
                           COUNT(*) FILTER (WHERE journal_kind='ORIGINAL')::bigint,
                           COUNT(*) FILTER (WHERE journal_kind='REVERSAL')::bigint,
                           MAX(created_at)
                    FROM fame_finance.journals
                    WHERE tenant_id=%s AND project_id=%s
                      AND posting_status='POSTED_TEST'
                ''', (tenantId, project_id)).fetchone()

                # True account-side net amounts (reversals have inverted debits/credits).
                # A ledger balance does NOT imply cash, budget available, or money received.
                accounts = conn.execute('''
                    SELECT l.account_code,
                           COALESCE(SUM(l.debit_minor),0)::bigint AS debit_minor,
                           COALESCE(SUM(l.credit_minor),0)::bigint AS credit_minor
                    FROM fame_finance.journals j
                    JOIN fame_finance.journal_lines l ON l.journal_id=j.journal_id
                    WHERE j.tenant_id=%s AND j.project_id=%s
                      AND j.posting_status='POSTED_TEST'
                    GROUP BY l.account_code
                    ORDER BY l.account_code
                ''', (tenantId, project_id)).fetchall()

                rows = conn.execute('''
                    SELECT journal_id::text, journal_kind, posting_status,
                           currency_code, reverses_journal_id::text,
                           commit_receipt::text, created_at
                    FROM fame_finance.journals
                    WHERE tenant_id=%s AND project_id=%s
                      AND posting_status='POSTED_TEST'
                    ORDER BY created_at DESC, journal_id DESC
                    LIMIT %s OFFSET %s
                ''', (tenantId, project_id, limit, offset)).fetchall()
        except PermissionError:
            raise HTTPException(403, 'FAME_PROJECT_PERMISSION_DENIED')

        return {
            'tenantId': tenantId,
            'projectId': project_id,
            'currencyCode': 'USD',
            'mode': 'SYNTHETIC_ONLY',
            'realMoneyEnabled': False,
            'paymentsEnabled': False,
            'ledger': {
                'journalCount': int(totals[0]),
                'originalCount': int(totals[1]),
                'reversalCount': int(totals[2]),
                'latestJournalAt': totals[3].isoformat() if totals[3] else None,
            },
            'accountTotals': [
                {
                    'accountCode': a[0],
                    'debitMinor': int(a[1]),
                    'creditMinor': int(a[2]),
                    'netDebitMinor': int(a[1] - a[2]),
                }
                for a in accounts
            ],
            'journals': [
                {
                    'journalId': r[0],
                    'journalKind': r[1],
                    'postingStatus': r[2],
                    'currencyCode': r[3],
                    'reversesJournalId': r[4],
                    'commitReceipt': r[5],
                    'createdAt': r[6].isoformat(),
                }
                for r in rows
            ],
            'pagination': {
                'limit': limit,
                'offset': offset,
                'returnedCount': len(rows),
                'hasMore': offset + len(rows) < int(totals[0]),
            },
            'disclaimer': 'Synthetic journal records only. Not cash or available budget.',
        }

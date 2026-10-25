"""HMAC-authenticated, fail-closed FastAPI gateway for the synthetic FAME ledger."""
from __future__ import annotations
import os
import re
import time
from uuid import UUID
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors
from .core import InvalidJournal, identifier, signature_ok
from .db import database
from .service import create_test_journal, reverse_test_journal, get_test_journal

app = FastAPI(title='FAME Ledger Authority', version='F1E.1', docs_url=None, redoc_url=None, openapi_url=None)

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Line(StrictModel):
    account_code: str
    debit_minor: int = Field(ge=0, le=10**12, strict=True)
    credit_minor: int = Field(ge=0, le=10**12, strict=True)

class BaseRequest(StrictModel):
    tenantId: str
    projectId: str
    actorId: str
    idempotencyKey: str

class PostRequest(BaseRequest):
    currencyCode: str = Field(pattern='^USD$')  # F1E.1 deliberately USD synthetic only.
    lines: list[Line] = Field(min_length=2, max_length=100)

class ReverseRequest(BaseRequest):
    originalJournalId: str

async def verify_hmac(request: Request):
    secret = os.getenv('FAME_SERVICE_SIGNING_SECRET', '')
    if len(secret) < 32 or secret.startswith('REPLACE_'):
        raise HTTPException(503, 'SIGNING_SECRET_NOT_CONFIGURED')
    timestamp = request.headers.get('x-fame-timestamp', '')
    nonce = request.headers.get('x-fame-nonce', '')
    supplied = request.headers.get('x-fame-signature', '')
    if not re.fullmatch(r'\d{10,13}', timestamp) or not re.fullmatch(r'[a-zA-Z0-9_-]{16,128}', nonce):
        raise HTTPException(401, 'INVALID_REQUEST_AUTHENTICATION')
    if abs(int(timestamp)-int(time.time())) > 300:
        raise HTTPException(401, 'STALE_REQUEST')
    full_path = request.url.path + ('?' + request.url.query if request.url.query else '')
    body = await request.body()
    if not signature_ok(secret, supplied, request.method, full_path, timestamp, nonce, body):
        raise HTTPException(401, 'INVALID_REQUEST_SIGNATURE')
    return {'nonce':nonce,'timestamp':int(timestamp)}


def consume_nonce(conn, nonce):
    # Durable replay defense. The nonce commits atomically with a successful request.
    try:
        conn.execute('INSERT INTO fame_finance.request_nonces(nonce) VALUES (%s)', (nonce,))
    except errors.UniqueViolation:
        raise HTTPException(401, 'REQUEST_NONCE_REPLAY')


def check_identifiers(data: dict):
    for field in ('tenantId','projectId','actorId','idempotencyKey'):
        try: identifier(data[field], field.upper())
        except InvalidJournal as exc: raise HTTPException(422, str(exc))


def db_operation(operation, data: dict, auth: dict):
    check_identifiers(data)
    try:
        with database() as conn:
            consume_nonce(conn, auth['nonce'])
            return operation(conn, data)
    except PermissionError:
        raise HTTPException(403, 'FAME_PROJECT_PERMISSION_DENIED')
    except InvalidJournal as exc:
        raise HTTPException(409 if 'IDEMPOTENCY_' in str(exc) or 'ALREADY_REVERSED' in str(exc) else 422, str(exc))
    except errors.UniqueViolation:
        raise HTTPException(409, 'UNIQUE_CONSTRAINT_CONFLICT')

@app.get('/healthz')
def health():
    return {'ok':True, 'component':'FAME_LEDGER_AUTHORITY', 'realMoneyEnabled':False,
            'atomicCommitProof':'REQUIRES_LIVE_POSTGRES_TEST'}

@app.post('/v1/journals/test')
async def post_test(data: PostRequest, auth=Depends(verify_hmac)):
    return db_operation(create_test_journal, data.model_dump(), auth)

@app.post('/v1/journals/test/reverse')
async def reverse_test(data: ReverseRequest, auth=Depends(verify_hmac)):
    return db_operation(reverse_test_journal, data.model_dump(), auth)

@app.get('/v1/journals/{journal_id}')
async def read_test(journal_id: str, tenantId: str, projectId: str, actorId: str,
                    auth=Depends(verify_hmac)):
    try:
        UUID(journal_id)
        for label, val in (('tenantId',tenantId),('projectId',projectId),('actorId',actorId)):
            identifier(val,label)
    except (ValueError, TypeError, InvalidJournal):
        raise HTTPException(422, 'INVALID_QUERY_IDENTIFIER')
    try:
        with database() as conn:
            consume_nonce(conn, auth['nonce'])
            result = get_test_journal(conn, tenant=tenantId, project=projectId, actor=actorId, journal_id=journal_id)
        if result is None: raise HTTPException(404, 'JOURNAL_NOT_FOUND')
        return result
    except PermissionError:
        raise HTTPException(403, 'FAME_PROJECT_PERMISSION_DENIED')

@app.get('/v1/readiness')
async def readiness(auth=Depends(verify_hmac)):
    with database() as conn:
        consume_nonce(conn, auth['nonce'])
        conn.execute('SELECT 1 FROM fame_finance.journals LIMIT 1')
    return {'pass':True,'databaseReachable':True,'syntheticAtomicDesignInstalled':True,
            'concurrentCommitProofVerified':False,'crashRecoveryProofVerified':False,
            'twoMemberIsolationProofVerified':False,'providerEvidenceVerified':False,
            'readyForRealMoney':False,'paymentsEnabled':False}

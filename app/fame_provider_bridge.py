"""FAME test ledger: bind a Stripe order to an authorized production; consume verified-event outbox.

Two distinct HMAC trust boundaries:
  * Wix/authorized ledger operator -> /bind uses existing FAME_SERVICE_SIGNING_SECRET.
  * Stripe event dispatcher -> /apply uses FAME_PROVIDER_BRIDGE_SECRET.

No general purpose ledger posting is granted to the provider. TEST ONLY.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from uuid import UUID

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from psycopg import errors

from .core import InvalidJournal, identifier, request_fingerprint, signature_ok
from .db import database
from .service import _persist, require_grant
from .fame_provider_bridge_core import paid_lines, refund_delta_lines, fee_refunded_cumulative, validate_payment


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class BindOrder(StrictModel):
    orderId: UUID
    tenantId: str
    projectId: str
    actorId: str
    listingId: str = Field(min_length=1, max_length=200)
    buyerKey: str = Field(min_length=3, max_length=200)
    sellerKey: str = Field(min_length=3, max_length=200)
    amountMinor: int = Field(ge=1, le=10_000_000, strict=True)
    feeMinor: int = Field(ge=0, le=10_000_000, strict=True)
    currencyCode: str = Field(pattern='^USD$')
    stripeSessionId: str = Field(pattern=r'^cs_test_[a-zA-Z0-9_]+$', max_length=255)


class VerifiedEvent(StrictModel):
    providerEventId: str = Field(pattern=r'^evt_[a-zA-Z0-9_]+$', max_length=255)
    eventType: str = Field(pattern=r'^(MARKETPLACE_PAID|MARKETPLACE_REFUND_UPDATED)$')
    orderId: UUID
    listingId: str = Field(min_length=1, max_length=200)
    buyerKey: str = Field(min_length=3, max_length=200)
    sellerKey: str = Field(min_length=3, max_length=200)
    amountMinor: int = Field(ge=1, le=10_000_000, strict=True)
    feeMinor: int = Field(ge=0, le=10_000_000, strict=True)
    refundedMinor: int = Field(ge=0, le=10_000_000, strict=True)
    currencyCode: str = Field(pattern='^USD$')
    stripeSessionId: str = Field(pattern=r'^cs_test_[a-zA-Z0-9_]+$', max_length=255)
    stripePaymentIntentId: str = Field(pattern=r'^pi_[a-zA-Z0-9_]+$', max_length=255)


def test_gate():
    if os.getenv('FAME_PROVIDER_BRIDGE_MODE', 'test') != 'test' or os.getenv('FAME_PROVIDER_BRIDGE_ENABLED') != '1':
        raise HTTPException(503, 'PROVIDER_TEST_BRIDGE_DISABLED')
    if os.getenv('FAME_REAL_MONEY_ENABLED', '').lower() in ('1', 'true', 'yes'):
        raise HTTPException(503, 'PROVIDER_TEST_BRIDGE_REFUSES_LIVE_MONEY')


async def verify_provider_hmac(request: Request):
    test_gate()
    secret = os.getenv('FAME_PROVIDER_BRIDGE_SECRET', '')
    if len(secret) < 32 or secret.startswith('REPLACE_'):
        raise HTTPException(503, 'PROVIDER_BRIDGE_SECRET_NOT_CONFIGURED')
    ts, nonce, supplied = (request.headers.get(k, '') for k in
                           ('x-fame-timestamp', 'x-fame-nonce', 'x-fame-signature'))
    if not re.fullmatch(r'\d{10}', ts) or not re.fullmatch(r'[A-Za-z0-9_-]{16,128}', nonce):
        raise HTTPException(401, 'INVALID_PROVIDER_AUTHENTICATION')
    if abs(int(time.time()) - int(ts)) > 300:
        raise HTTPException(401, 'STALE_PROVIDER_REQUEST')
    path = request.url.path + (('?' + request.url.query) if request.url.query else '')
    raw = await request.body()
    if len(raw) > 16_384 or not signature_ok(secret, supplied, request.method, path, ts, nonce, raw):
        raise HTTPException(401, 'INVALID_PROVIDER_SIGNATURE')
    return {'nonce': nonce}


def register_provider_bridge_routes(app, verify_ledger_hmac, consume_nonce):
    @app.post('/v1/provider-orders/test/bind')
    async def bind_test_order(data: BindOrder, auth=Depends(verify_ledger_hmac)):
        test_gate()
        try:
            validate_payment(data.amountMinor, data.feeMinor)
            for field in ('tenantId','projectId','actorId'):
                identifier(getattr(data,field),field.upper())
            requested = (
                str(data.orderId),data.tenantId,data.projectId,data.actorId,data.listingId,
                data.buyerKey,data.sellerKey,data.amountMinor,data.feeMinor,data.currencyCode,
                data.stripeSessionId)
            with database() as conn:
                consume_nonce(conn,auth['nonce'])
                require_grant(conn,tenant_id=data.tenantId,project_id=data.projectId,
                              actor_id=data.actorId,permission='POST_TEST')
                row = conn.execute('''
                    INSERT INTO fame_finance.provider_order_bindings_test
                      (order_id,tenant_id,project_id,actor_id,listing_id,buyer_key,seller_key,
                       amount_minor,fee_minor,currency_code,stripe_session_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (order_id) DO NOTHING RETURNING order_id
                ''', requested).fetchone()
                if row is None:
                    old = conn.execute('''
                        SELECT order_id::text,tenant_id,project_id,actor_id,listing_id,buyer_key,
                               seller_key,amount_minor,fee_minor,currency_code,stripe_session_id
                        FROM fame_finance.provider_order_bindings_test WHERE order_id=%s
                    ''',(str(data.orderId),)).fetchone()
                    if tuple(old or ()) != requested:
                        raise HTTPException(409,'PROVIDER_ORDER_BINDING_CONFLICT')
                conn.execute('''INSERT INTO fame_finance.provider_order_state_test(order_id)
                                VALUES (%s) ON CONFLICT DO NOTHING''',(str(data.orderId),))
            return {'ok':True,'orderId':str(data.orderId),'bound':True,'idempotentReplay':row is None,
                    'testOnly':True}
        except PermissionError:
            raise HTTPException(403,'FAME_PROJECT_PERMISSION_DENIED')
        except InvalidJournal as exc:
            raise HTTPException(422,str(exc))

    @app.post('/v1/provider-events/test/apply')
    async def apply_test_provider_event(data: VerifiedEvent, auth=Depends(verify_provider_hmac)):
        try:
            validate_payment(data.amountMinor,data.feeMinor)
            if data.refundedMinor > data.amountMinor:
                raise InvalidJournal('PROVIDER_REFUND_EXCEEDS_ORDER')
            if data.eventType == 'MARKETPLACE_PAID' and data.refundedMinor != 0:
                raise InvalidJournal('PAID_EVENT_REFUND_NONZERO')
            if data.eventType == 'MARKETPLACE_REFUND_UPDATED' and data.refundedMinor == 0:
                raise InvalidJournal('REFUND_EVENT_ZERO')
            payload = data.model_dump(mode='json')
            payload_hash = request_fingerprint(payload)
            with database() as conn:
                consume_nonce(conn,auth['nonce'])
                # Ignore exact duplicate transport events, but detect payload mutation.
                old = conn.execute('''
                    SELECT payload_hash,journal_id::text,result_code
                    FROM fame_finance.provider_event_inbox_test WHERE provider_event_id=%s
                ''',(data.providerEventId,)).fetchone()
                if old:
                    if old[0] != payload_hash:
                        raise HTTPException(409,'PROVIDER_EVENT_FINGERPRINT_CONFLICT')
                    return {'ok':True,'idempotentReplay':True,'journalId':old[1],
                            'result':old[2],'testOnly':True}
                binding = conn.execute('''
                    SELECT tenant_id,project_id,actor_id,listing_id,buyer_key,seller_key,
                           amount_minor,fee_minor,currency_code,stripe_session_id
                    FROM fame_finance.provider_order_bindings_test WHERE order_id=%s
                ''',(str(data.orderId),)).fetchone()
                if not binding:
                    raise HTTPException(409,'PROVIDER_ORDER_NOT_BOUND')
                (tenant,project,actor,listing,buyer,seller,amount,fee,currency,session)=binding
                if (listing,buyer,seller,amount,fee,currency,session)!=(data.listingId,data.buyerKey,
                     data.sellerKey,data.amountMinor,data.feeMinor,data.currencyCode,data.stripeSessionId):
                    raise HTTPException(409,'PROVIDER_ORDER_SOURCE_MISMATCH')
                state = conn.execute('''
                    SELECT paid_journal_id::text,refunded_minor,refunded_fee_minor
                    FROM fame_finance.provider_order_state_test WHERE order_id=%s FOR UPDATE
                ''',(str(data.orderId),)).fetchone()
                if not state:
                    raise HTTPException(409,'PROVIDER_ORDER_STATE_MISSING')
                previous_paid, previous_refund, previous_fee = state
                journal_id = previous_paid
                result_code = 'BUSINESS_EVENT_ALREADY_APPLIED'
                if data.eventType == 'MARKETPLACE_PAID':
                    if not previous_paid:
                        require_grant(conn,tenant_id=tenant,project_id=project,
                                      actor_id=actor,permission='POST_TEST')
                        result = _persist(conn,tenant=tenant,project=project,actor=actor,
                            key=f'stripe-paid:{data.orderId}',currency='USD',
                            lines=paid_lines(amount,fee),kind='ORIGINAL',reverses_id=None,
                            fingerprint=request_fingerprint({'orderId':str(data.orderId),
                                'eventKind':'PAID_TEST','amountMinor':amount,'feeMinor':fee}))
                        journal_id = result['journalId']
                        conn.execute('''UPDATE fame_finance.provider_order_state_test
                                        SET paid_journal_id=%s,updated_at=now()
                                        WHERE order_id=%s''',(journal_id,str(data.orderId)))
                        result_code='POSTED_TEST'
                else:
                    if not previous_paid:
                        raise HTTPException(409,'PROVIDER_PAID_EVENT_NOT_POSTED')
                    if data.refundedMinor > previous_refund:
                        require_grant(conn,tenant_id=tenant,project_id=project,
                                      actor_id=actor,permission='POST_TEST')
                        refund_lines = refund_delta_lines(amount,fee,previous_refund,data.refundedMinor)
                        result = _persist(conn,tenant=tenant,project=project,actor=actor,
                            key=f'stripe-refund:{data.orderId}:{data.refundedMinor}',currency='USD',
                            lines=refund_lines,kind='ORIGINAL',reverses_id=None,
                            fingerprint=request_fingerprint({'orderId':str(data.orderId),
                                'eventKind':'REFUND_ADJUSTMENT_TEST','fromMinor':previous_refund,
                                'toMinor':data.refundedMinor}))
                        journal_id = result['journalId']
                        conn.execute('''UPDATE fame_finance.provider_order_state_test
                            SET refunded_minor=%s,refunded_fee_minor=%s,updated_at=now()
                            WHERE order_id=%s''',(data.refundedMinor,
                                fee_refunded_cumulative(amount,fee,data.refundedMinor),str(data.orderId)))
                        result_code='POSTED_TEST'
                conn.execute('''
                    INSERT INTO fame_finance.provider_event_inbox_test
                     (provider_event_id,order_id,event_type,payload_hash,journal_id,result_code)
                    VALUES (%s,%s,%s,%s,%s,%s)
                ''',(data.providerEventId,str(data.orderId),data.eventType,payload_hash,
                     journal_id,result_code))
            return {'ok':True,'idempotentReplay':False,'journalId':journal_id,
                    'result':result_code,'testOnly':True}
        except PermissionError:
            raise HTTPException(403,'FAME_PROJECT_PERMISSION_DENIED')
        except InvalidJournal as exc:
            raise HTTPException(422,str(exc))
        except errors.UniqueViolation:
            # An in-flight duplicate provider event can safely be retried.
            raise HTTPException(409,'PROVIDER_EVENT_CONCURRENT_RETRY')

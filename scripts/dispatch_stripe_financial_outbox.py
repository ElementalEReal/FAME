"""Dispatch durable verified Stripe TEST events from Neon into signed FAME ledger TEST API.

Explicit CLI invocation or a controlled scheduled job only. No real money, payouts,
product fulfillment, or arbitrary SQL values from browser requests.

Environment (private):
  FAME_STRIPE_DATABASE_URL = Neon TEST connection URL
  FAME_PROVIDER_BRIDGE_SECRET = unique >=32-character bridge secret
  FAME_LEDGER_API_URL = ledger TEST API HTTPS base URL
  FAME_PROVIDER_BRIDGE_ALLOWED_HOST = exact hostname of TEST ledger API
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request,urlopen

import psycopg
from app.core import signature

PATH='/v1/provider-events/test/apply'


def target() -> str:
    value=os.environ.get('FAME_LEDGER_API_URL','').rstrip('/')
    url=urlsplit(value)
    allowed=os.environ.get('FAME_PROVIDER_BRIDGE_ALLOWED_HOST','')
    if not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        raise RuntimeError('INVALID_LEDGER_API_BASE_URL')
    if url.hostname in ('localhost','127.0.0.1','::1'):
        if url.scheme!='http' or os.environ.get('FAME_PROVIDER_BRIDGE_ALLOW_LOCALHOST')!='1':
            raise RuntimeError('LOCALHOST_REQUIRES_EXPLICIT_OPT_IN')
    elif url.scheme!='https' or url.hostname!=allowed:
        raise RuntimeError('LEDGER_HOST_NOT_ALLOWED')
    return value


def claim(db_url: str, limit: int):
    # Claim retryable events for 60 seconds without holding DB locks during HTTP.
    with psycopg.connect(db_url,connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute('''
                WITH pending AS (
                  SELECT provider_event_id FROM fame_stripe.financial_outbox_test
                  WHERE delivered_at IS NULL AND next_attempt_at <= now()
                  ORDER BY created_at,provider_event_id
                  FOR UPDATE SKIP LOCKED LIMIT %s
                )
                UPDATE fame_stripe.financial_outbox_test o
                SET delivery_attempts=o.delivery_attempts+1,
                    next_attempt_at=now()+interval '60 seconds'
                FROM pending WHERE o.provider_event_id=pending.provider_event_id
                RETURNING o.provider_event_id,o.payload,o.payload_hash,o.delivery_attempts
            ''',(limit,))
            return cur.fetchall()


def update_result(db_url: str, event_id: str, *, delivered: bool, journal_id=None, code=''):
    with psycopg.connect(db_url,connect_timeout=5) as conn:
        with conn.cursor() as cur:
            if delivered:
                cur.execute('''UPDATE fame_stripe.financial_outbox_test
                    SET delivered_at=now(),ledger_journal_id=%s,last_error_code=NULL
                    WHERE provider_event_id=%s AND delivered_at IS NULL''',(journal_id,event_id))
            else:
                # Capped exponential retry. Never discard a financial event automatically.
                cur.execute('''UPDATE fame_stripe.financial_outbox_test
                    SET last_error_code=%s,
                        next_attempt_at=now()+((LEAST(3600,30*power(2,LEAST(delivery_attempts,7))))::integer * interval '1 second')
                    WHERE provider_event_id=%s AND delivered_at IS NULL''',(code[:80],event_id))


def send(base: str, secret: str, payload):
    body=json.dumps(payload,sort_keys=True,separators=(',',':')).encode('utf8')
    ts=str(int(time.time()))
    nonce=secrets.token_urlsafe(24)
    sig=signature(secret,'POST',PATH,ts,nonce,body)
    req=Request(base+PATH,data=body,method='POST',headers={
        'Content-Type':'application/json','x-fame-timestamp':ts,
        'x-fame-nonce':nonce,'x-fame-signature':sig})
    try:
        with urlopen(req,timeout=20) as response:
            result=json.load(response)
            if response.status==200 and result.get('ok') is True:
                return True,result.get('journalId'),''
            return False,None,'UNEXPECTED_LEDGER_RESPONSE'
    except HTTPError as exc:
        return False,None,f'HTTP_{exc.code}'
    except (URLError,TimeoutError,OSError,ValueError):
        return False,None,'LEDGER_TRANSPORT_ERROR'


def run(limit: int, dry_run: bool) -> int:
    if os.getenv('FAME_STRIPE_MODE')!='test' or os.getenv('FAME_PROVIDER_BRIDGE_MODE')!='test':
        raise RuntimeError('TEST_MODE_REQUIRED')
    db_url=os.environ.get('FAME_STRIPE_DATABASE_URL','')
    if not db_url:
        raise RuntimeError('FAME_STRIPE_DATABASE_URL_REQUIRED')
    if dry_run:
        # No claims, no network calls. Lists counts only.
        with psycopg.connect(db_url,connect_timeout=5) as conn:
            rows=conn.execute('''SELECT COUNT(*),COUNT(*) FILTER (WHERE delivered_at IS NOT NULL)
                                 FROM fame_stripe.financial_outbox_test''').fetchone()
        print(json.dumps({'mode':'DRY_RUN','outboxEvents':rows[0], 'delivered':rows[1]}))
        return 0
    secret=os.getenv('FAME_PROVIDER_BRIDGE_SECRET','')
    if len(secret)<32:
        raise RuntimeError('BRIDGE_SECRET_NOT_CONFIGURED')
    base=target()
    for event_id,payload,expected_hash,attempt in claim(db_url,limit):
        if hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode('utf8')).hexdigest()!=expected_hash:
            update_result(db_url,event_id,delivered=False,code='SOURCE_PAYLOAD_HASH_MISMATCH')
            print(json.dumps({'eventId':event_id,'delivered':False,'result':'SOURCE_PAYLOAD_HASH_MISMATCH'}))
            continue
        ok,journal_id,code=send(base,secret,payload)
        update_result(db_url,event_id,delivered=ok,journal_id=journal_id,code=code)
        print(json.dumps({'eventId':event_id,'delivered':ok,'attempt':attempt,
                          'result':'ACK' if ok else code}))
    return 0


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--limit',type=int,default=10)
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    if not (1 <= args.limit <= 100):
        parser.error('limit must be 1..100')
    raise SystemExit(run(args.limit,args.dry_run))

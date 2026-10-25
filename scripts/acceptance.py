"""Live local API acceptance; run inside ledger-api container after granting actor."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import secrets
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from app.core import signature

BASE=os.getenv('FAME_API_URL','http://127.0.0.1:8769').rstrip('/')
SECRET=os.environ['FAME_SERVICE_SIGNING_SECRET']


def signed(method, path, payload=None, *, nonce=None, timestamp=None):
    body=(json.dumps(payload,separators=(',',':')).encode() if payload is not None else b'')
    timestamp=timestamp or str(int(time.time()))
    nonce=nonce or secrets.token_urlsafe(24)
    sig=signature(SECRET,method,path,timestamp,nonce,body)
    req=Request(BASE+path, data=body if method!='GET' else None, method=method,
                headers={'Content-Type':'application/json', 'x-fame-timestamp':timestamp,
                         'x-fame-nonce':nonce,'x-fame-signature':sig})
    try:
        with urlopen(req,timeout=30) as r:
            return r.status,json.load(r)
    except HTTPError as ex:
        try:err=json.loads(ex.read())
        except Exception:err={'detail':str(ex)}
        return ex.code,err


def read_journal(tenant,project,actor,jid):
    path='/v1/journals/'+jid+'?'+urlencode({'tenantId':tenant,'projectId':project,'actorId':actor})
    return signed('GET',path)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--tenant',required=True);p.add_argument('--project',required=True)
    p.add_argument('--actor',required=True);p.add_argument('--verify-journal',default=None)
    args=p.parse_args()
    if args.verify_journal:
        status,result=read_journal(args.tenant,args.project,args.actor,args.verify_journal)
        passed=status==200 and result.get('journalId')==args.verify_journal and len(result.get('lines',[]))==2
        print('FAME_F1E1_RESTART_RECOVERY_RESULT',json.dumps({'pass':passed,'httpStatus':status,
            'journalId':args.verify_journal, 'savedLineCount':len(result.get('lines',[])),
            'postingStatus':result.get('postingStatus'),'realMoneyEnabled':False},indent=2))
        return 0 if passed else 1

    key='f1e1.acceptance.'+secrets.token_hex(10)
    post={'tenantId':args.tenant,'projectId':args.project,'actorId':args.actor,'idempotencyKey':key,
          'currencyCode':'USD', 'lines':[{'account_code':'TEST_EXPENSE','debit_minor':500000,'credit_minor':0},
                                         {'account_code':'TEST_PAYABLE','debit_minor':0,'credit_minor':500000}]}
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:signed('POST','/v1/journals/test',post),range(12)))
    all_201=[s==200 for s,_ in results]
    ids=[r.get('journalId') for _,r in results]
    receipts=[r.get('commitReceipt') for _,r in results]
    jid=ids[0]
    rev=dict(tenantId=args.tenant,projectId=args.project,actorId=args.actor,
             idempotencyKey='reversal.'+key,originalJournalId=jid)
    with ThreadPoolExecutor(max_workers=8) as pool:
        reversals=list(pool.map(lambda _:signed('POST','/v1/journals/test/reverse',rev),range(12)))
    rs=[s==200 for s,_ in reversals]
    reverse_ids=[r.get('journalId') for _,r in reversals]
    b_status,_=read_journal(args.tenant,args.project,'unauthorized.member.b',jid)
    same_key_changed={**post,'lines':[{'account_code':'TEST_EXPENSE','debit_minor':10000,'credit_minor':0},
                                      {'account_code':'TEST_PAYABLE','debit_minor':0,'credit_minor':10000}]}
    changed_status,_=signed('POST','/v1/journals/test',same_key_changed)
    other_reversal_status,_=signed('POST','/v1/journals/test/reverse',dict(rev,idempotencyKey='different.'+key))
    read_status,read_result=read_journal(args.tenant,args.project,args.actor,jid)
    passed=(all(all_201) and len(set(ids))==1 and len(set(receipts))==1
            and sum(not r.get('idempotentReplay',True) for _,r in results)==1
            and all(rs) and len(set(reverse_ids))==1
            and sum(not r.get('idempotentReplay',True) for _,r in reversals)==1
            and b_status==403 and changed_status==409 and other_reversal_status==409
            and read_status==200 and len(read_result.get('lines',[]))==2)
    output={'pass':passed, 'testJournalId':jid, 'reversalJournalId':reverse_ids[0],
            'concurrentPostRequests':len(results), 'createdPostCount':sum(not r.get('idempotentReplay',True) for _,r in results),
            'concurrentReversalRequests':len(reversals),
            'createdReversalCount':sum(not r.get('idempotentReplay',True) for _,r in reversals),
            'uniqueCommitReceiptCount':len(set(receipts)),
            'unauthorizedActorHttpStatus':b_status,'idempotencyPayloadConflictStatus':changed_status,
            'doubleReversalConflictStatus':other_reversal_status,
            'savedLineCount':len(read_result.get('lines',[])),
            'postingStatus':'POSTED_TEST','paymentsEnabled':False,
            'crashRecoveryProof':'PENDING_RESTART_TEST', 'wixMemberIsolationProof':'PENDING_IN_WIX'}
    print('FAME_F1E1_POSTGRES_ACCEPTANCE_RESULT',json.dumps(output,indent=2))
    print('\nNEXT: docker compose restart ledger-api')
    print('THEN: docker compose exec ledger-api python -m scripts.acceptance'
          f' --tenant {args.tenant} --project {args.project} --actor {args.actor} --verify-journal {jid}')
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())

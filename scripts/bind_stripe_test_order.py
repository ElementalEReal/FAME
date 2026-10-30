"""Explicit TEST-only signed ledger binding for an already-created Stripe Checkout order.

Use with verified order details from trusted Wix server / Stripe API, NOT from browser input.
Signing secret stays in process environment; never put it in CLI args or logs.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from urllib.parse import urlsplit
from urllib.request import Request,urlopen
from app.core import signature

PATH='/v1/provider-orders/test/bind'


def main():
    p=argparse.ArgumentParser()
    for name in ('order-id','tenant','project','actor','listing','buyer','seller','stripe-session-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--amount-minor',type=int,required=True)
    p.add_argument('--fee-minor',type=int,required=True)
    p.add_argument('--dry-run',action='store_true')
    a=p.parse_args()
    data={'orderId':a.order_id,'tenantId':a.tenant,'projectId':a.project,'actorId':a.actor,
          'listingId':a.listing,'buyerKey':a.buyer,'sellerKey':a.seller,
          'amountMinor':a.amount_minor,'feeMinor':a.fee_minor,'currencyCode':'USD',
          'stripeSessionId':a.stripe_session_id}
    if a.dry_run:
        print('TEST order binding prepared; no API call was made.')
        return
    base=os.environ['FAME_LEDGER_API_URL'].rstrip('/')
    host=urlsplit(base)
    if (host.scheme!='https' and not (host.scheme=='http' and host.hostname in ('localhost','127.0.0.1'))) or host.path or host.query:
        raise RuntimeError('INVALID_API_URL')
    secret=os.environ['FAME_SERVICE_SIGNING_SECRET']
    if len(secret)<32:
        raise RuntimeError('SIGNING_SECRET_NOT_CONFIGURED')
    raw=json.dumps(data,separators=(',',':')).encode('utf8')
    timestamp=str(int(time.time()))
    nonce=secrets.token_urlsafe(24)
    signed=signature(secret,'POST',PATH,timestamp,nonce,raw)
    req=Request(base+PATH,data=raw,method='POST',headers={
        'Content-Type':'application/json','x-fame-timestamp':timestamp,
        'x-fame-nonce':nonce,'x-fame-signature':signed})
    with urlopen(req,timeout=20) as response:
        result=json.load(response)
    print(json.dumps({'ok':result.get('ok'), 'bound':result.get('bound'),
                      'testOnly':result.get('testOnly')},sort_keys=True))


if __name__=='__main__':
    main()

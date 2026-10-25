"""Send one test-only journal. Uses only the Python standard library."""
import json, os, secrets, sys, time
from urllib.request import Request, urlopen
from app.core import signature

tenant, project, actor = sys.argv[1:4]
url = os.getenv('FAME_API_URL', 'http://127.0.0.1:8769')
secret = os.environ['FAME_SERVICE_SIGNING_SECRET']
payload = {'tenantId':tenant, 'projectId':project, 'actorId':actor,
    'idempotencyKey':'f1e1-local-'+secrets.token_hex(10), 'currencyCode':'USD',
    'lines':[{'account_code':'TEST_EXPENSE','debit_minor':500000,'credit_minor':0},
             {'account_code':'TEST_PAYABLE','debit_minor':0,'credit_minor':500000}]}
body = json.dumps(payload, separators=(',', ':')).encode()
path='/v1/journals/test'; timestamp=str(int(time.time()));nonce=secrets.token_urlsafe(24)
sig=signature(secret,'POST',path,timestamp,nonce,body)
request=Request(url+path, data=body, method='POST', headers={
    'Content-Type':'application/json','x-fame-timestamp':timestamp,
    'x-fame-nonce':nonce, 'x-fame-signature':sig})
with urlopen(request, timeout=15) as r:print(r.read().decode())

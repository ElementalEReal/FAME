"""Isolated read-only Wix -> Render reviewer proof handshake.

Does not import financial governance, payment, database, or TEST modules.
"""
import hashlib
import hmac
import json
import os
import re
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()
ROUTE = '/v1/live/diagnostics/reviewer-proof'
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX48 = re.compile(r'[0-9a-f]{48}\Z')
MEMBER = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')


def reject():
    return JSONResponse(status_code=403, content={'ok': False, 'code': 'PROOF_REJECTED'}, headers={'Cache-Control': 'no-store'})


def verify(raw: bytes, headers: dict, method: str, path: str, now: float | None = None) -> bool:
    if method != 'POST' or path != ROUTE or len(raw) > 4096:
        return False
    timestamp = headers.get('x-fame-timestamp', '')
    nonce = headers.get('x-fame-nonce', '')
    signature = headers.get('x-fame-signature', '')
    member = headers.get('x-fame-live-member', '')
    proof = headers.get('x-fame-member-proof', '')
    if not (re.fullmatch(r'[0-9]{10,12}', timestamp) and HEX48.fullmatch(nonce)
            and HEX64.fullmatch(signature) and HEX64.fullmatch(proof)
            and MEMBER.fullmatch(member)):
        return False
    now = time.time() if now is None else now
    if abs(now-int(timestamp)) > 300:
        return False
    bridge_key = os.getenv('FAME_LIVE_BRIDGE_SECRET', '')
    proof_key = os.getenv('FAME_LIVE_REVIEW_PROOF_SECRET', '')
    if len(bridge_key.encode()) < 32 or len(proof_key.encode()) < 32:
        return False
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict) or set(data) != {'reviewer_member_id', 'purpose'} or data['reviewer_member_id'] != member or data['purpose'] != 'READ_ONLY_REVIEWER_PROOF':
        return False
    digest = hashlib.sha256(raw).hexdigest()
    message = '\n'.join(['POST', ROUTE, timestamp, nonce, digest])
    expected_signature = hmac.new(bridge_key.encode(), message.encode(), hashlib.sha256).hexdigest()
    expected_proof = hmac.new(proof_key.encode(), (message+'\n'+member).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature) or not hmac.compare_digest(proof, expected_proof):
        return False
    allowed = {x.strip() for x in os.getenv('FAME_LIVE_REVIEWER_MEMBER_IDS','').split(',') if x.strip()}
    return bool(allowed) and member in allowed


@router.post(ROUTE)
async def reviewer_proof(request: Request):
    if os.getenv('FAME_LIVE_REVIEW_PING_ENABLED') != '1':
        return JSONResponse(status_code=404, content={'detail': 'Not Found'})
    raw = await request.body()
    if len(raw) > 4096:
        return reject()
    if not verify(raw, request.headers, request.method, request.url.path):
        return reject()
    return JSONResponse(status_code=200, content={'ok': True, 'result': 'REVIEWER_PROOF_VERIFIED_READ_ONLY'}, headers={'Cache-Control': 'no-store'})

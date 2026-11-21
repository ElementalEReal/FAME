"""FAME LIVE independent reviewer authorization.

Only call after a trusted Wix backend has authenticated
the member and Render has verified the signed request.
"""

import os
import re

from app.live_policy import PurchaseRejected


MEMBER_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def require_live_reviewer(member_id: str) -> str:
    if not isinstance(member_id, str):
        raise PurchaseRejected("LIVE_REVIEWER_INVALID")

    if not MEMBER_ID.fullmatch(member_id):
        raise PurchaseRejected("LIVE_REVIEWER_INVALID")

    configured = os.getenv(
        "FAME_LIVE_REVIEWER_MEMBER_IDS", ""
    )

    allowed = {
        value.strip()
        for value in configured.split(",")
        if value.strip()
    }

    if not allowed:
        raise PurchaseRejected(
            "LIVE_REVIEWERS_NOT_CONFIGURED"
        )

    if member_id not in allowed:
        raise PurchaseRejected(
            "LIVE_REVIEWER_FORBIDDEN"
        )

    return member_id

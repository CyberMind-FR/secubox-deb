# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.assist_match — pure, decentralized offer↔request matcher.

Every node computes matches identically from its own journal copy (no
coordinator). match_id is a deterministic BLAKE2b of (offer_id|req_id) so both
sides derive the same id. Expiry is fail-closed (offer/request stale past
created_at+ttl_s). A match is 'ready' only when BOTH sides have posted a signed
ASSIST_MATCH_ACCEPT and the underlying offer+request are still active.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, List, Mapping, Tuple

from .assist import _by  # dict/LogEntry-tolerant op iterator (yields payloads)
from .model import Op


def match_id(offer_id: str, req_id: str) -> str:
    return hashlib.blake2b(f"{offer_id}|{req_id}".encode("utf-8"),
                           digest_size=32).hexdigest()


def _expired(created_at: str, ttl_s: int, now_ts: str) -> bool:
    try:
        c = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        n = datetime.strptime(now_ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True  # unparseable → fail-closed
    return n >= c + timedelta(seconds=int(ttl_s))


def active_offers(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    revoked = {p.get("offer_id") for p in _by(entries, Op.ASSIST_OFFER_REVOKE)}
    out = []
    for p in _by(entries, Op.ASSIST_OFFER):
        if p.get("offer_id") in revoked:
            continue
        if _expired(p.get("created_at", ""), p.get("ttl_s", 0), now_ts):
            continue
        out.append(p)
    return out


def active_open_requests(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    out = []
    for p in _by(entries, Op.ASSIST_REQUEST_OPEN):
        if _expired(p.get("created_at", ""), p.get("ttl_s", 0), now_ts):
            continue
        out.append(p)
    return out


def _compatible(offer: dict, request: dict) -> bool:
    if not (set(offer.get("tags", [])) & set(request.get("tags", []))):
        return False
    os_, rs = offer.get("scope"), request.get("scope")
    if os_ and rs and os_ != rs:
        return False
    return True


def matches(entries: List[Mapping[str, Any]], now_ts: str
            ) -> List[Tuple[dict, dict, str]]:
    offers = active_offers(entries, now_ts)
    requests = active_open_requests(entries, now_ts)
    out = []
    for o in offers:
        for r in requests:
            if _compatible(o, r):
                out.append((o, r, match_id(o["offer_id"], r["req_id"])))
    return out


def match_ready(entries: List[Mapping[str, Any]], mid: str, now_ts: str) -> bool:
    accepts = [p for p in _by(entries, Op.ASSIST_MATCH_ACCEPT)
               if p.get("match_id") == mid]
    sides = {p.get("side") for p in accepts}
    if not {"offer", "request"} <= sides:
        return False
    # underlying offer+request must still be active
    live_mids = {mid_ for _, _, mid_ in matches(entries, now_ts)}
    return mid in live_mids

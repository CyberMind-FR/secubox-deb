# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.rendezvous — turn a ready match into a session on the
REQUESTER side. Sovereignty: this node only ever opens a session for ITS OWN
open request (request.issued_by == self_did); a match never opens anything on
its own — the caller (ctl) still runs the operator-consented assist_session_open
with center_did = the offerer. Single active session invariant preserved.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional

try:
    from annuaire import assist_match as _mm
    from annuaire import assist as _assist
except Exception:  # pragma: no cover — import shim for isolated tests
    _mm = _assist = None


def ready_matches(entries: List[Mapping[str, Any]], self_did: str,
                  now_ts: str) -> List[dict]:
    if _mm is None:
        return []
    out = []
    for offer, request, mid in _mm.matches(entries, now_ts):
        if request.get("issued_by") != self_did:
            continue  # sovereignty: only our own open requests
        if _mm.match_ready(entries, mid, now_ts):
            out.append({"match_id": mid, "offer_id": offer["offer_id"],
                        "req_id": request["req_id"], "offerer_did": offer["issued_by"]})
    return out


def should_open(entries: List[Mapping[str, Any]], self_did: str,
                now_ts: str) -> Optional[dict]:
    if _assist is not None and _assist.active_session(entries, self_did, now_ts) is not None:
        return None  # single-session invariant
    rm = ready_matches(entries, self_did, now_ts)
    return rm[0] if rm else None

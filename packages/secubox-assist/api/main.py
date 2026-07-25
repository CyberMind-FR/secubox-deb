# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: assist API — reads in-process, mutations delegate to ctl."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt

sys.path.insert(0, os.environ.get("ANNUAIRE_LIB", "/usr/lib/secubox/annuaire"))
from annuaire.log import Journal          # noqa: E402
from annuaire import assist               # noqa: E402
from annuaire import assist_match         # noqa: E402
from annuaire.crypto import public_from_private, did_from_pubkey  # noqa: E402
from assist import rendezvous             # noqa: E402  (local sibling package)

app = FastAPI(title="SecuBox Assist")
CTL = ["/usr/sbin/secubox-assistctl"]
MESH_IFACE = "wg-mesh"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entries():
    try:
        return list(Journal(os.environ.get(
            "ANNUAIRE_JOURNAL", "/var/lib/secubox/annuaire/journal.db")).iter_entries())
    except Exception:
        return []


def _self_did():
    path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    try:
        raw = bytes.fromhex(open(path).read().strip())
        return did_from_pubkey(public_from_private(raw))
    except Exception:
        return None


def _ctl(*args):
    r = subprocess.run(CTL + list(args), capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise HTTPException(status_code=400, detail=r.stderr.strip() or "ctl failed")
    try:
        return json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return {"raw": r.stdout}


@app.get("/status")
async def status():
    sid = _self_did()
    active = None
    if sid:
        try:
            active = assist.active_session(_entries(), sid, _now())
        except assist.AssistError:
            active = {"error": "multiple-active-sessions"}
    return {"module": "assist", "enabled": True, "mesh_iface": MESH_IFACE,
            "has_active_session": bool(active)}


@app.get("/health")
async def health():
    return {"status": "ok", "module": "assist"}


@app.get("/sessions", dependencies=[Depends(require_jwt)])
async def sessions():
    sid = _self_did()
    entries = _entries()
    return {"pending": assist.pending_requests(entries, sid) if sid else [],
            "active_session": (assist.active_session(entries, sid, _now())
                               if sid else None)}


class RequestBody(BaseModel):
    center_did: str
    mode: str
    scope: str
    duration_s: int
    reason: str


@app.post("/request", dependencies=[Depends(require_jwt)])
async def make_request(b: RequestBody):
    return _ctl("request", b.center_did, "--mode", b.mode, "--scope", b.scope,
                "--duration", str(b.duration_s), "--reason", b.reason)


class OpenBody(BaseModel):
    req_id: str
    center_did: str
    duration_s: int


@app.post("/open", dependencies=[Depends(require_jwt)])
async def open_session(b: OpenBody):
    return _ctl("open", b.req_id, "--center", b.center_did, "--duration", str(b.duration_s))


class SessionRef(BaseModel):
    session_id: str
    reason: str | None = None


@app.post("/close", dependencies=[Depends(require_jwt)])
async def close_session(b: SessionRef):
    return _ctl("close", b.session_id, *(["--reason", b.reason] if b.reason else []))


class ConsoleBody(BaseModel):
    session_id: str
    duration_s: int = 900


@app.post("/console/grant", dependencies=[Depends(require_jwt)])
async def console_grant(b: ConsoleBody):
    return _ctl("console-grant", b.session_id, "--duration", str(b.duration_s))


@app.post("/console/revoke", dependencies=[Depends(require_jwt)])
async def console_revoke(b: SessionRef):
    return _ctl("console-revoke", b.session_id)


# --------------------------------------------------------------------------- #
# Assist marketplace (dual offer/request) — sous-projet assist-dual. Reads are
# computed in-process from the journal (annuaire.assist_match / rendezvous);
# writes delegate to secubox-assistctl (signed journal appends).
# --------------------------------------------------------------------------- #

@app.get("/offers", dependencies=[Depends(require_jwt)])
async def offers():
    return assist_match.active_offers(_entries(), _now())


@app.get("/requests/open", dependencies=[Depends(require_jwt)])
async def requests_open():
    return assist_match.active_open_requests(_entries(), _now())


@app.get("/matches", dependencies=[Depends(require_jwt)])
async def matches():
    sid = _self_did()
    if sid is None:
        return []
    return rendezvous.ready_matches(_entries(), sid, _now())


class OfferBody(BaseModel):
    tags: list[str]
    scope: str | None = None
    ttl_s: int


@app.post("/offer", dependencies=[Depends(require_jwt)])
async def offer(b: OfferBody):
    return _ctl("offer", "--tags", ",".join(b.tags),
                *(["--scope", b.scope] if b.scope else []), "--ttl", str(b.ttl_s))


class OfferRef(BaseModel):
    offer_id: str


@app.post("/offer/revoke", dependencies=[Depends(require_jwt)])
async def offer_revoke(b: OfferRef):
    return _ctl("offer-revoke", b.offer_id)


class OpenRequestBody(BaseModel):
    tags: list[str]
    scope: str | None = None
    ttl_s: int
    reason: str


@app.post("/request/open", dependencies=[Depends(require_jwt)])
async def request_open(b: OpenRequestBody):
    return _ctl("request-open", "--tags", ",".join(b.tags),
                *(["--scope", b.scope] if b.scope else []), "--ttl", str(b.ttl_s),
                "--reason", b.reason)


class MatchAcceptBody(BaseModel):
    offer_id: str
    req_id: str
    side: str


@app.post("/match/accept", dependencies=[Depends(require_jwt)])
async def match_accept(b: MatchAcceptBody):
    return _ctl("match-accept", b.offer_id, b.req_id, b.side)


class JoinLinkBody(BaseModel):
    ref: str
    ttl_s: int


@app.post("/joinlink", dependencies=[Depends(require_jwt)])
async def joinlink(b: JoinLinkBody):
    return _ctl("joinlink", "--for", b.ref, "--ttl", str(b.ttl_s))

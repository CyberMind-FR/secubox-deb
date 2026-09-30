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
from secubox_core.auth import require_lecture
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


@app.get("/status", dependencies=[Depends(require_lecture)])
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


def _fiches(entries) -> dict:
    """DID → dernière publication de nœud (boxname, ddns…) du journal."""
    out = {}
    for e in entries:
        op = getattr(e, "op", None) or (e.get("op") if isinstance(e, dict) else None)
        payload = getattr(e, "payload", None) or (e.get("payload") if isinstance(e, dict) else None)
        if str(getattr(op, "value", op)) == "node_publish" and isinstance(payload, dict):
            if payload.get("did"):
                out[payload["did"]] = payload
    return out


def _noeuds(entries) -> dict:
    """DID → nom de box, d'après les publications de nœuds du journal."""
    return {d: f.get("boxname") for d, f in _fiches(entries).items() if f.get("boxname")}


@app.get("/requests/open", dependencies=[Depends(require_jwt)])
async def requests_open():
    """Demandes ouvertes du maillage, avec leur nœud d'origine et « la mienne »
    (#1711) : on répond aux demandes des autres, pas aux siennes."""
    entries = _entries()
    moi, noms = _self_did(), _noeuds(entries)
    out = []
    for r in assist_match.active_open_requests(entries, _now()):
        de = r.get("issued_by") or ""
        out.append({**r, "de_moi": de == moi,
                    "noeud": noms.get(de) or (de.split(":")[-1][:8] if de else "?")})
    return out


# --------------------------------------------------------------------------- #
# Délégation web (#1720) — côté CENTRE. Une box qui m'a ouvert une session
# d'assistance ET accordé la console me laisse administrer son interface, au
# nom du compte qui clique ici, jusqu'à l'échéance qu'ELLE a signée.
# --------------------------------------------------------------------------- #
from annuaire import delegation as _delegation  # noqa: E402


def _priv() -> bytes:
    path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    return bytes.fromhex(open(path).read().strip())


@app.get("/delegations")
async def delegations(user=Depends(require_jwt)):
    sid = _self_did()
    if sid is None:
        return []
    entries = _entries()
    fiches = _fiches(entries)
    out = []
    for d in assist.sessions_centre(entries, sid, _now()):
        f = fiches.get(d["box_did"], {})
        out.append({**d, "noeud": f.get("boxname") or d["box_did"].split(":")[-1][:8],
                    "domaine": f.get("ddns") or ""})
    return out


class AssertionBody(BaseModel):
    session_id: str


@app.post("/delegation/assertion")
async def delegation_assertion(b: AssertionBody, user=Depends(require_jwt)):
    """Adresse d'entrée sur la box aidée, avec une assertion signée par ce nœud
    (60 s, usage unique) au nom du compte connecté."""
    sid = _self_did()
    entries = _entries()
    d = next((x for x in assist.sessions_centre(entries, sid, _now()) if x["session_id"] == b.session_id), None) if sid else None
    if d is None:
        raise HTTPException(status_code=404, detail="aucune délégation active pour cette session")
    f = _fiches(entries).get(d["box_did"], {})
    domaine = f.get("ddns") or ""
    if not domaine:
        raise HTTPException(status_code=409, detail="domaine de la box inconnu (fiche de nœud non publiée)")
    compte = str((user or {}).get("sub") or "").lower()
    try:
        jeton = _delegation.emettre(_priv(), d["box_did"], compte, b.session_id)
    except _delegation.Refus as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        from assist import audit  # noqa: PLC0415
        audit.record("delegation_assertion", b.session_id, compte,
                     {"box": d["box_did"], "noeud": f.get("boxname"), "fin": d["fin"]})
    except Exception:  # noqa: BLE001
        pass
    return {"url": f"https://admin.{domaine}/api/v1/auth/delegation/entrer?a={jeton}",
            "noeud": f.get("boxname") or "", "fin": d["fin"]}


class AnswerBody(BaseModel):
    req_id: str
    ttl_s: int = 3600


@app.post("/request/answer", dependencies=[Depends(require_jwt)])
async def request_answer(b: AnswerBody):
    """RÉPONDRE À UNE DEMANDE en un geste (#1711) : publier une offre aux
    étiquettes (et à la portée) de la demande, puis accepter l'appariement côté
    offre. Tout reste des écritures signées du journal — traçables — et le
    demandeur garde le dernier mot : il accepte à son tour, côté demande."""
    entries = _entries()
    req = next((r for r in assist_match.active_open_requests(entries, _now())
                if r.get("req_id") == b.req_id), None)
    if req is None:
        raise HTTPException(status_code=404, detail="demande inconnue ou expirée")
    if req.get("issued_by") == _self_did():
        raise HTTPException(status_code=409, detail="c'est une demande de ce nœud")
    offre = _ctl("offer", "--tags", ",".join(req.get("tags") or []),
                 *(["--scope", req["scope"]] if req.get("scope") else []),
                 "--ttl", str(b.ttl_s))
    offer_id = offre.get("offer_id")
    if not offer_id:
        raise HTTPException(status_code=502, detail="offre non publiée")
    acc = _ctl("match-accept", offer_id, b.req_id, "offer")
    return {"offer_id": offer_id, "match_id": acc.get("match_id"),
            "noeud": _noeuds(entries).get(req.get("issued_by"), "")}


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

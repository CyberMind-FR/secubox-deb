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


def _cotes_acceptes(entries: List[Mapping[str, Any]], mid: str, offre: dict, demande: dict):
    """(offre_acceptee, demande_acceptee) pour `mid`. Même règle que `match_ready` (annuaire) : chaque acceptation n'est créditée que si ses propres
    identifiants produisent `mid` ET si son auteur possède le côté qu'il prétend (l'auteur de l'offre pour « offer », celui de la demande pour « request »)."""
    off_ok = dem_ok = False
    for e in entries:
        op, auteur, payload = _mm._op_author_payload(e)
        if op != "assist_match_accept" or auteur is None or payload.get("match_id") != mid:
            continue
        oid, rid = payload.get("offer_id"), payload.get("req_id")
        if oid is None or rid is None or _mm.match_id(oid, rid) != mid:
            continue
        if payload.get("side") == "offer" and oid == offre.get("offer_id") and auteur == offre.get("issued_by"):
            off_ok = True
        elif payload.get("side") == "request" and rid == demande.get("req_id") and auteur == demande.get("issued_by"):
            dem_ok = True
    return off_ok, dem_ok


def candidate_matches(entries: List[Mapping[str, Any]], self_did: str, now_ts: str) -> List[dict]:
    """Les paires offre ↔ demande COMPATIBLES qui nous concernent (offreur OU demandeur), avec l'état des deux côtés (#2546).

    `ready_matches` n'en rend que les paires déjà acceptées des deux côtés, et seulement pour NOS demandes : les boutons « Accepter » posés sur cette liste
    n'apparaissaient donc jamais. Ici, une paire compatible est visible dès qu'elle existe ; `prete` = les deux côtés ont accepté (c'est `ready_matches`,
    inchangé, qui sert à ouvrir la session)."""
    if _mm is None or not self_did:
        return []
    out = []
    for offre, demande, mid in _mm.matches(entries, now_ts):
        o_de, d_de = offre.get("issued_by"), demande.get("issued_by")
        if o_de == d_de or self_did not in (o_de, d_de):
            continue                                                       # pas de paire avec soi-même, ni celles des autres
        off_ok, dem_ok = _cotes_acceptes(entries, mid, offre, demande)
        out.append({"match_id": mid, "offer_id": offre["offer_id"], "req_id": demande["req_id"],
                    "offerer_did": o_de, "requester_did": d_de,
                    "mon_cote": "offer" if o_de == self_did else "request",
                    "offre_acceptee": off_ok, "demande_acceptee": dem_ok, "prete": off_ok and dem_ok,
                    "tags": sorted(set(offre.get("tags", [])) & set(demande.get("tags", [])))})
    return out


def should_open(entries: List[Mapping[str, Any]], self_did: str,
                now_ts: str) -> Optional[dict]:
    if _assist is not None and _assist.active_session(entries, self_did, now_ts) is not None:
        return None  # single-session invariant
    rm = ready_matches(entries, self_did, now_ts)
    return rm[0] if rm else None

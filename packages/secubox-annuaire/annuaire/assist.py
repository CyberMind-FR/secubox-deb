# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: annuaire.assist — resolve assistance state from the signed log.

Pure functions over journal entries (LogEntry OR dict — via grants._op/_payload).
Every resolver takes the box's own `self_did`: a SESSION/CONSOLE op authored by
anyone else (federated) is IGNORED (sovereignty). Expiry is fail-closed: past
`expires_ts` a session/console is inactive even with no explicit close op.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional

from .grants import _author, _op, _payload, active_grants  # dict/LogEntry-tolerant accessors
from .model import Op


class AssistError(Exception):
    """Raised on a broken invariant (e.g. >1 active session)."""


def _by(entries, op: Op):
    for entry in entries:
        if _op(entry) == op.value:
            yield _payload(entry)


def _self_by(entries, op: Op, self_did: str):
    """Yield payloads of `op` entries AUTHORED BY self_did (sovereign + self-cert).

    A self-scoped assist op (SESSION_OPEN/CLOSE, CONSOLE_GRANT/REVOKE) is always
    authored by the box itself (author == issued_by == self_did — see the verbs).
    import_entries federates ANY validly-signed op, so a mesh peer can sign one
    naming issued_by=self_did with its OWN key; trusting payload.issued_by over
    the authenticated author lets that forged op count (phantom session → the
    single-session invariant trips → the victim's real sessions are DoS'd).
    Bind to the verified author, fail-closed on a missing/foreign author."""
    for entry in entries:
        if _op(entry) != op.value:
            continue
        author = _author(entry)
        if not author or author != self_did:
            continue
        p = _payload(entry)
        if p.get("issued_by") != self_did:  # self-certification consistency
            continue
        yield p


def _selfcert_by(entries, op: Op):
    """Yield payloads of `op` entries whose VERIFIED author == payload issued_by.

    For ops that legitimately carry a non-self issued_by (ASSIST_REQUEST in
    standing mode is center-authored), the sovereignty scope lives in the
    caller's issued_by logic — but a forged op claiming a DIFFERENT issued_by
    than its real signer must never be honored. Fail-closed on missing author."""
    for entry in entries:
        if _op(entry) != op.value:
            continue
        p = _payload(entry)
        author = _author(entry)
        if not author or author != p.get("issued_by"):
            continue
        yield p


def active_session(entries: List[Mapping[str, Any]], self_did: str,
                   now_ts: str) -> Optional[dict]:
    """Return the single active session opened BY self_did, or None.

    Active = a SESSION_OPEN (issued_by == self_did) whose session_id has no
    later SESSION_CLOSE and whose expires_ts is still in the future (RFC3339
    lexicographic compare — all timestamps are UTC 'Z', so string order == time
    order). Raises AssistError if more than one is active (invariant breach).
    """
    closed = {p.get("session_id")
              for p in _self_by(entries, Op.ASSIST_SESSION_CLOSE, self_did)}
    live = []
    for p in _self_by(entries, Op.ASSIST_SESSION_OPEN, self_did):
        sid = p.get("session_id")
        if sid in closed:
            continue
        if str(now_ts) >= str(p.get("expires_ts", "")):
            continue  # fail-closed past hard-cap
        live.append(p)
    if len(live) > 1:
        raise AssistError("multiple-active-sessions")
    return live[0] if live else None


def console_active(entries: List[Mapping[str, Any]], session_id: str,
                   now_ts: str) -> bool:
    """True if a CONSOLE_GRANT for session_id is live (no later REVOKE, not expired)."""
    revoked = {p.get("session_id") for p in _selfcert_by(entries, Op.ASSIST_CONSOLE_REVOKE)}
    if session_id in revoked:
        # a REVOKE after the last GRANT kills it; treat any revoke as terminal
        # (console is short-lived and re-granted explicitly)
        return False
    for p in _selfcert_by(entries, Op.ASSIST_CONSOLE_GRANT):
        if p.get("session_id") != session_id:
            continue
        if str(now_ts) < str(p.get("expires_ts", "")):
            return True
    return False


def pending_requests(entries: List[Mapping[str, Any]], self_did: str) -> List[dict]:
    """REQUESTs relevant to this box not yet accepted.

    Includes box-authored requests (issued_by == self_did) and — for standing
    mode — center-authored requests, leaving the standing-grant check to the
    caller (verbs/ctl) which has the grant matrix. Accepted requests drop out.
    """
    accepted = {p.get("req_id") for p in _by(entries, Op.ASSIST_ACCEPT)}
    out = []
    for p in _selfcert_by(entries, Op.ASSIST_REQUEST):
        if p.get("req_id") in accepted:
            continue
        if p.get("issued_by") != self_did and p.get("mode") != "standing":
            continue  # per-incident request authored by someone else: not ours
        out.append(p)
    return out


def can_open(entries: List[Mapping[str, Any]], req_id: str,
             self_did: str, now_ts: str) -> tuple[bool, str]:
    """Whether the box may open a session for req_id: request exists, was
    accepted, is authorized for this box (self-authored, or standing mode
    BACKED BY an active capability="assist" Grant), and NO session is
    currently active (single-session invariant).

    Per-incident mode: the box-authored ASSIST_REQUEST IS the authority —
    no grant needed. Standing mode: the request alone is NOT enough; the
    center must additionally hold an active, SELF-issued (issued_by ==
    self_did — see active_grants()'s sovereignty filter) capability="assist"
    grant naming that same center_did, or the open is refused.
    """
    reqs = {p.get("req_id"): p for p in _selfcert_by(entries, Op.ASSIST_REQUEST)}
    if req_id not in reqs:
        return False, "no-such-request"
    accepted = {p.get("req_id") for p in _by(entries, Op.ASSIST_ACCEPT)}
    if req_id not in accepted:
        return False, "not-accepted"
    req = reqs[req_id]
    if req.get("issued_by") != self_did and req.get("mode") != "standing":
        return False, "not-authorized"
    if req.get("mode") == "standing":
        grants = active_grants(entries, self_did)
        has_assist_grant = any(
            g.get("capability") == "assist" and g.get("center_did") == req.get("center_did")
            for g in grants.values()
        )
        if not has_assist_grant:
            return False, "no-standing-grant"
    if active_session(entries, self_did, now_ts) is not None:
        return False, "session-already-active"
    return True, "ok"


# ---------------------------------------------------------------------------
# Délégation web (#1720) : un compte du CENTRE administre la box aidée tant que
# la box l'a consenti deux fois — session ouverte ET accord de console — et
# pas une seconde de plus. Tout est signé par la box elle-même ; un pair ne
# peut ni ouvrir ni prolonger une délégation chez un autre.
# ---------------------------------------------------------------------------

def _signe_par(entries, op: Op, did: str):
    """Payloads de `op` signés par `did` ET le déclarant comme émetteur."""
    for entry in entries:
        if _op(entry) != op.value:
            continue
        p = _payload(entry)
        if _author(entry) == did and p.get("issued_by") == did:
            yield p


def _fenetre(entries, box_did: str, session_id: str, now_ts: str) -> Optional[str]:
    """Échéance de la délégation sur `session_id` de `box_did`, ou None.

    Il faut, TOUS signés par la box : la session ouverte, non fermée, non
    échue ; un accord de console pour elle, non révoqué, non échu. L'échéance
    est la plus proche des deux."""
    fermees = {p.get("session_id") for p in _signe_par(entries, Op.ASSIST_SESSION_CLOSE, box_did)}
    if session_id in fermees:
        return None
    session = None
    for p in _signe_par(entries, Op.ASSIST_SESSION_OPEN, box_did):
        if p.get("session_id") == session_id and str(now_ts) < str(p.get("expires_ts", "")):
            session = p
    if session is None:
        return None
    revoquees = {p.get("session_id") for p in _signe_par(entries, Op.ASSIST_CONSOLE_REVOKE, box_did)}
    if session_id in revoquees:
        return None
    fin_console = None
    for p in _signe_par(entries, Op.ASSIST_CONSOLE_GRANT, box_did):
        if p.get("session_id") == session_id and str(now_ts) < str(p.get("expires_ts", "")):
            fin_console = max(fin_console or "", str(p.get("expires_ts")))
    if fin_console is None:
        return None
    return min(fin_console, str(session.get("expires_ts")))


def delegation_active(entries: List[Mapping[str, Any]], self_did: str,
                      center_did: str, session_id: str, now_ts: str) -> Optional[str]:
    """CÔTÉ BOX AIDÉE : échéance (RFC3339) de la délégation de `center_did` sur
    `session_id`, ou None. La session doit viser CE centre."""
    for p in _signe_par(entries, Op.ASSIST_SESSION_OPEN, self_did):
        if p.get("session_id") == session_id and p.get("center_did") == center_did:
            return _fenetre(entries, self_did, session_id, now_ts)
    return None


def sessions_centre(entries: List[Mapping[str, Any]], center_did: str,
                    now_ts: str) -> List[dict]:
    """CÔTÉ CENTRE : les sessions où `center_did` est l'aidant et que la box a
    ouvertes à la délégation (accord de console actif) — [{box_did,
    session_id, fin}]."""
    out = []
    for entry in entries:
        if _op(entry) != Op.ASSIST_SESSION_OPEN.value:
            continue
        p = _payload(entry)
        box = _author(entry)
        if not box or box != p.get("issued_by") or p.get("center_did") != center_did:
            continue
        fin = _fenetre(entries, box, p.get("session_id"), now_ts)
        if fin:
            out.append({"box_did": box, "session_id": p.get("session_id"), "fin": fin})
    return out

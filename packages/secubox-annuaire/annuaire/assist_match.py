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

Author-bound like the socle resolvers (assist.py/grants.py): any signed mesh
member can author a well-formed op, so payload fields such as `issued_by` or
`side` are attacker-controlled and MUST be cross-checked against the entry's
AUTHENTICATED `author` (LogEntry.author / dict["author"], set by the Journal
from the signing key — see log.py). Without this check: (a) anyone could
revoke anyone else's offer, (b) a single signer could forge both sides of a
match acceptance, (c) issued_by could be spoofed to a victim's DID.

Ids are author-self-certifying (see author_prefix/_id_matches_author): an
offer_id/req_id is only admitted for an author whose DID-derived prefix it
carries. Without this, offer_id/req_id are free-form attacker-chosen
strings, and `offers_by_id`/`requests_by_id` (keyed by bare id) would
collapse two different authors' entries onto the same key — a signed peer
could publish a SHADOW ASSIST_OFFER carrying a victim's exact offer_id,
win the id lookup (last-writer-wins), pass its own author-check trivially,
and hijack the victim's real match without the victim ever accepting.
Requiring the id to carry its author's own prefix makes ids globally
unique per author, so this shadowing is structurally impossible.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, List, Mapping, Optional, Tuple

from .assist import _by  # dict/LogEntry-tolerant op iterator (yields payloads)
from .grants import _op, _payload  # dict/LogEntry-tolerant op/payload accessors
from .model import Op


def _op_author_payload(entry):
    """Return (op_str, author, payload), tolerating LogEntry (attributes) and
    dict. `author` is the AUTHENTICATED signer of this journal entry — NEVER
    trust payload["issued_by"] as a proxy for it."""
    if isinstance(entry, dict):
        return _op(entry), entry.get("author"), _payload(entry)
    return _op(entry), getattr(entry, "author", None), _payload(entry)


def match_id(offer_id: str, req_id: str) -> str:
    return hashlib.blake2b(f"{offer_id}|{req_id}".encode("utf-8"),
                           digest_size=32).hexdigest()


def author_prefix(did: str) -> str:
    """32-hex (128-bit) prefix deterministically derived from the author's DID.

    128 bits so an id is a security-boundary identifier a peer cannot forge by
    grinding a targeted prefix collision (a 48-bit prefix was brute-forceable in
    days on a cluster, which would reopen the id-shadowing consent forgery once
    the live join-path escalates a forged match). See project_assist_dual_marketplace.
    """
    return hashlib.blake2b((did or "").encode("utf-8"), digest_size=16).hexdigest()


def _id_matches_author(entry_id: str, issued_by: str) -> bool:
    """An offer_id/req_id is only valid for its author if it carries that
    author's prefix: "<author_prefix>-<random>". This makes ids globally
    unique per author — a peer cannot mint an id under a victim's prefix
    (its own issued_by drives the required prefix), nor shadow a victim's
    exact id (that id carries the victim's prefix, not the peer's). This is
    what closes the id-shadowing consent-forgery: a signed peer C publishing
    ASSIST_OFFER{offer_id=<A's id>, issued_by=C} now fails this check (A's id
    doesn't carry C's prefix) and is dropped at admission, so the shared
    offers_by_id/requests_by_id maps can never collapse two different
    authors' entries onto the same key.
    """
    if not entry_id or not issued_by:
        return False
    return entry_id.startswith(author_prefix(issued_by) + "-")


def _parse_ts(ts: str) -> datetime:
    """Parse an RFC 3339 timestamp, tz-aware.

    Accepts both the 'Z'-suffixed, second-precision form used in tests/fixtures
    AND model.now_rfc3339()'s datetime.isoformat() rendering (optional
    microseconds, explicit '+00:00' offset) — the real shape produced by the
    AssistOffer/AssistOpenRequest default_factory.
    """
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)  # tz-aware given a UTC offset is present


def _expired(created_at: str, ttl_s: int, now_ts: str) -> bool:
    try:
        c = _parse_ts(created_at)
        n = _parse_ts(now_ts)
        return n >= c + timedelta(seconds=int(ttl_s))
    except (ValueError, TypeError):
        return True  # unparseable → fail-closed


def active_offers(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    """Offers admitted ONLY when author == issued_by (spoofed issued_by is
    dropped) AND the offer_id carries that author's prefix (id-shadowing
    guard — see _id_matches_author). A revoke withdraws an offer ONLY when
    the revoke's own author matches the offer's author AND the revoke's own
    offer_id carries that author's prefix — a foreign revoke (any other
    signer, or one targeting a well-formed id it doesn't own) is ignored,
    since that signer never owned the offer_id in the first place.
    """
    # (offer_id, revoke_author) pairs — who actually signed each revoke.
    revoked = set()
    for entry in entries:
        op, author, payload = _op_author_payload(entry)
        if op == Op.ASSIST_OFFER_REVOKE.value:
            if author is None or not _id_matches_author(payload.get("offer_id"), author):
                continue  # revoke doesn't carry the revoker's own prefix
            revoked.add((payload.get("offer_id"), author))

    out = []
    for entry in entries:
        op, author, payload = _op_author_payload(entry)
        if op != Op.ASSIST_OFFER.value:
            continue
        if author is None or author != payload.get("issued_by"):
            continue  # author-bound: spoofed issued_by rejected
        offer_id = payload.get("offer_id")
        if offer_id is None:
            continue  # fail-closed: no id, can't be revoked or matched safely
        if not _id_matches_author(offer_id, author):
            continue  # id-shadowing guard: id doesn't carry this author's prefix
        if (offer_id, author) in revoked:
            continue  # only a same-author revoke can withdraw this offer
        if _expired(payload.get("created_at", ""), payload.get("ttl_s", 0), now_ts):
            continue
        out.append(payload)
    return out


def active_open_requests(entries: List[Mapping[str, Any]], now_ts: str) -> List[dict]:
    """Requests admitted ONLY when author == issued_by (spoofed issued_by,
    e.g. naming a victim's DID, is dropped) AND the req_id carries that
    author's prefix (id-shadowing guard — see _id_matches_author)."""
    out = []
    for entry in entries:
        op, author, payload = _op_author_payload(entry)
        if op != Op.ASSIST_REQUEST_OPEN.value:
            continue
        if author is None or author != payload.get("issued_by"):
            continue  # author-bound: spoofed issued_by rejected
        req_id = payload.get("req_id")
        if req_id is None:
            continue  # fail-closed: no id, can't be matched safely
        if not _id_matches_author(req_id, author):
            continue  # id-shadowing guard: id doesn't carry this author's prefix
        if _expired(payload.get("created_at", ""), payload.get("ttl_s", 0), now_ts):
            continue
        out.append(payload)
    return out


def _compatible(offer: dict, request: dict) -> bool:
    if not (set(offer.get("tags", [])) & set(request.get("tags", []))):
        return False
    os_, rs = offer.get("scope"), request.get("scope")
    if os_ is not None and rs is not None and os_ != rs:
        return False
    return True


def matches(entries: List[Mapping[str, Any]], now_ts: str
            ) -> List[Tuple[dict, dict, str]]:
    offers = active_offers(entries, now_ts)
    requests = active_open_requests(entries, now_ts)
    out = []
    for o in offers:
        offer_id = o.get("offer_id")
        if offer_id is None:
            continue  # fail-closed: never crash on a malformed offer
        for r in requests:
            req_id = r.get("req_id")
            if req_id is None:
                continue  # fail-closed: never crash on a malformed request
            if _compatible(o, r):
                out.append((o, r, match_id(offer_id, req_id)))
    return out


def match_ready(entries: List[Mapping[str, Any]], mid: str, now_ts: str) -> bool:
    """A match is ready only when BOTH an offer-side and a request-side
    ASSIST_MATCH_ACCEPT exist for `mid`, each authored by the party that
    actually owns that side — the offer's author (per active_offers) for
    side="offer", the request's author (per active_open_requests) for
    side="request". A single signer posting both sides (forging mutual
    consent) never satisfies both checks unless they legitimately own both
    the offer AND the request. The underlying offer+request must also still
    be active.

    Crucially, an accept's own (offer_id, req_id) pair MUST itself hash to
    `mid` before it can be credited at all. Without this, an attacker who
    owns their own active offer/request (o2/r2, passing the author-binding
    checks trivially) could post accepts carrying `match_id=mid` — some
    OTHER pair's match id, e.g. A's offer + B's request — while pointing
    offer_id/req_id at their own o2/r2. That would forge mutual consent for
    a rendezvous (mid) the attacker was never a party to. Requiring
    match_id(offer_id, req_id) == mid closes this: an accept can only ever
    speak for the exact pair that produces the mid it's posted against.
    """
    offers_by_id = {o["offer_id"]: o for o in active_offers(entries, now_ts)}
    requests_by_id = {r["req_id"]: r for r in active_open_requests(entries, now_ts)}

    offer_side_ok = False
    request_side_ok = False
    for entry in entries:
        op, author, payload = _op_author_payload(entry)
        if op != Op.ASSIST_MATCH_ACCEPT.value or payload.get("match_id") != mid:
            continue
        if author is None:
            continue
        offer_id = payload.get("offer_id")
        req_id = payload.get("req_id")
        if offer_id is None or req_id is None:
            continue  # fail-closed: no ids, can't be bound to mid
        if match_id(offer_id, req_id) != mid:
            continue  # this accept's own ids don't produce mid — not credited
        side = payload.get("side")
        if side == "offer":
            offer = offers_by_id.get(offer_id)
            if offer is not None and author == offer.get("issued_by"):
                offer_side_ok = True
        elif side == "request":
            request = requests_by_id.get(req_id)
            if request is not None and author == request.get("issued_by"):
                request_side_ok = True

    if not (offer_side_ok and request_side_ok):
        return False
    # underlying offer+request must still be active
    live_mids = {mid_ for _, _, mid_ in matches(entries, now_ts)}
    return mid in live_mids

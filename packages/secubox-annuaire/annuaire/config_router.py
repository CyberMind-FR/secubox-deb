# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: config_router
Push routing — verify center signature + grant, then compose+apply layers
(feat/centers-grants-remote-config, Task 6).

route_config() walks the journal's CONFIG_PUBLISH entries and, for every
scope that has at least one active grant (grants.active_grants) or a local
override file on disk, composes the ordered baseline/override/local layer
texts (annuaire.model.LAYER_ORDER) and applies them via
config_apply.apply_composed(). A CONFIG_PUBLISH is only a candidate
baseline/override source if ALL of the following hold:

  1. its publisher currently holds the exclusive grant for that exact
     (scope, layer) (grants.can_push) — a push from anyone else is not
     authority, it is a PROPOSAL;
  2. its signature verifies against canonical_bytes(payload) using the
     publisher's Ed25519 public key (payload is the ConfigBlob WITHOUT
     sig/signer_did — the same form the publisher signed, see verbs.py::
     publish_config, and the same form the journal stores as entry.payload);
  3. its content_hash matches BLAKE2b-256(payload text) — a corrupted or
     tampered inline blob is rejected even from a granted, correctly-signed
     publisher.

Anything that fails one of these is appended to the returned "proposals"
list and NEVER applied — it sits there for an operator/review flow (grant
the missing authority and re-push, or discard).

Publisher pubkey resolution
----------------------------
annuaire.model.LogEntry carries no author_pubkey_hex field — Journal.append()
only accepts it as a transient, write-time argument for signature
verification; it is not persisted as part of the chained entry. The durable
record of "did X owns pubkey Y" is the Identity payload of that did's
GENESIS/AUTO_ADD/INVITE_ACCEPT entry (payload_type == "Identity",
payload["pubkey"]) — this mirrors annuaire.log.Journal._author_pubkey()
exactly, just walking the in-memory `entries` list instead of the SQLite
table. A publisher with no such entry anywhere in `entries` cannot be
verified here and is routed to proposals (reason "bad-signature") — the
same fail-closed posture as the journal's own write path.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from .config_apply import _blake2b_hex, apply_composed, blob_text
from .crypto import canonical_bytes, verify
from .grants import active_grants, can_push
from .model import LAYER_ORDER

Entry = Union[Mapping[str, Any], Any]  # dict (subscript) or LogEntry-like (attribute)


# ---------------------------------------------------------------------------
# Entry-shape tolerance — same idiom as grants.py: LogEntry (attribute) or
# plain dict (subscript), interchangeably in the same list.
# ---------------------------------------------------------------------------

def _op(entry: Entry) -> Any:
    op = getattr(entry, "op", None)
    if op is None and isinstance(entry, dict):
        op = entry.get("op")
    return op


def _payload(entry: Entry) -> Dict[str, Any]:
    payload = getattr(entry, "payload", None)
    if payload is None and isinstance(entry, dict):
        payload = entry.get("payload")
    return payload or {}


def _payload_type(entry: Entry) -> Any:
    pt = getattr(entry, "payload_type", None)
    if pt is None and isinstance(entry, dict):
        pt = entry.get("payload_type")
    return pt


def _author(entry: Entry) -> Any:
    author = getattr(entry, "author", None)
    if author is None and isinstance(entry, dict):
        author = entry.get("author")
    return author


def _sig(entry: Entry) -> Any:
    sig = getattr(entry, "sig", None)
    if sig is None and isinstance(entry, dict):
        sig = entry.get("sig")
    return sig


def _resolve_pubkey(entries: List[Entry], did: Optional[str]) -> Optional[str]:
    """Latest Identity payload's pubkey for *did*, or None (fail-closed).

    Mirrors annuaire.log.Journal._author_pubkey(): scans for the most recent
    payload_type == "Identity" entry whose payload["did"] == did and reads
    its "pubkey" field. Entries are walked in list order (== chain height
    order), so a later Identity entry for the same did wins.
    """
    if not did:
        return None
    pub: Optional[str] = None
    for entry in entries:
        if _payload_type(entry) != "Identity":
            continue
        payload = _payload(entry)
        if payload.get("did") == did:
            pub = payload.get("pubkey")
    return pub


def route_config(
    entries: List[Entry],
    target_dir: str,
    self_did: Optional[str],
    local_dir: str,
) -> Dict[str, Any]:
    """Verify + apply every routable scope's config; the rest go to proposals.

    For each scope that has ≥1 active grant (grants.active_grants) OR a
    local override file (<local_dir>/<scope>.toml), gather the ordered
    layer texts (LAYER_ORDER: baseline < override < local) — baseline/
    override come from the newest verified CONFIG_PUBLISH of the granted
    center for that (scope, layer); local comes from disk if present — then
    apply_composed() it into target_dir. A CONFIG_PUBLISH whose publisher
    lacks the grant for its own (scope, layer), or that fails signature or
    content_hash verification, is dropped into "proposals" and never
    applied.

    self_did is accepted for interface symmetry with the apply_pending/
    apply_blob call sites (self-publish loop guard). It is not used to
    filter here: grant ownership is exclusive by construction, so a
    self-authored CONFIG_PUBLISH is only ever a layer source when this node
    itself holds the grant for that (scope, layer) — which is already the
    correct outcome.

    Returns:
        {"applied": [<apply_composed result>, ...], "proposals": [...]}
    """
    grant_map = active_grants(entries)  # {(scope, layer): grant_payload}

    # Newest verified (scope, layer) candidate text, keyed by (scope, layer).
    candidates: Dict[Tuple[str, str], Tuple[int, str]] = {}
    proposals: List[Dict[str, Any]] = []

    for entry in entries:
        if _op(entry) != "config_publish":
            continue

        payload = _payload(entry)
        scope = payload.get("scope")
        layer = payload.get("layer", "baseline")
        publisher = payload.get("publisher") or _author(entry)
        version = payload.get("version", 0)
        content_hash = payload.get("content_hash")
        config_id = payload.get("config_id")

        proposal = {
            "config_id": config_id,
            "publisher": publisher,
            "scope": scope,
            "layer": layer,
            "version": version,
        }

        if not scope or not publisher:
            proposals.append({**proposal, "reason": "malformed-blob"})
            continue

        if not can_push(entries, publisher, scope, layer):
            proposals.append({**proposal, "reason": "no-grant"})
            continue

        pub_hex = _resolve_pubkey(entries, publisher)
        sig = _sig(entry)
        if not pub_hex or not sig or not verify(pub_hex, canonical_bytes(payload), sig):
            proposals.append({**proposal, "reason": "bad-signature"})
            continue

        text = blob_text(payload.get("payload"))
        if text is None:
            proposals.append({**proposal, "reason": "no-inline-text"})
            continue

        if not content_hash or _blake2b_hex(text) != content_hash:
            proposals.append({**proposal, "reason": "hash-mismatch"})
            continue

        key = (scope, layer)
        best = candidates.get(key)
        if best is None or version >= best[0]:
            candidates[key] = (version, text)

    local_root = Path(local_dir)
    scopes = {scope for (scope, _layer) in grant_map.keys()}
    if local_root.is_dir():
        for f in local_root.glob("*.toml"):
            scopes.add(f.stem)

    applied: List[Dict[str, Any]] = []
    for scope in sorted(scopes):
        ordered_texts: List[str] = []
        for layer in LAYER_ORDER:
            if layer == "local":
                local_file = local_root / f"{scope}.toml"
                if local_file.is_file():
                    ordered_texts.append(local_file.read_text())
                continue
            cand = candidates.get((scope, layer))
            if cand is not None:
                ordered_texts.append(cand[1])
        if not ordered_texts:
            continue
        applied.append(apply_composed(scope, ordered_texts, target_dir))

    return {"applied": applied, "proposals": proposals}

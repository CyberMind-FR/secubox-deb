# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: grants
Config-property resolution — who owns which (scope, layer) delegated
config authority, derived exclusively from the journal.

A center holds delegated authority over a (scope, layer) pair iff a
GRANT_ISSUE for that pair exists and has not since been withdrawn by a
GRANT_REVOKE carrying the same grant_id. Ownership is exclusive: at most
one center holds a given (scope, layer) at a time (validate_issue enforces
this on the write path — the log itself just records what happened).

Entries may be either plain mappings with "op"/"payload" keys (as used by
the test fixtures below) or annuaire.log.LogEntry objects — the pydantic
model that annuaire.log.Journal.iter_entries() actually yields, where "op"
and "payload" are attributes, not subscripts. Callers can pass
list(journal.iter_entries()) directly; _op()/_payload() below accept
either shape transparently. Op is a str Enum, so comparing the resolved
value to the literal "grant_issue"/"grant_revoke" strings works whether
the caller passes Op members or bare strings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple, Union

from .model import NON_DELEGATABLE

GrantKey = Tuple[str, str]
Entry = Union[Mapping[str, Any], Any]  # dict (subscript) or LogEntry-like (attribute)


def _op(entry: Entry) -> Any:
    """Return entry.op if present (LogEntry), else entry["op"] (dict)."""
    op = getattr(entry, "op", None)
    if op is None and isinstance(entry, dict):
        op = entry.get("op")
    return op


def _payload(entry: Entry) -> Dict[str, Any]:
    """Return entry.payload if present (LogEntry), else entry["payload"] (dict)."""
    payload = getattr(entry, "payload", None)
    if payload is None and isinstance(entry, dict):
        payload = entry.get("payload")
    return payload or {}


def _author(entry: Entry) -> Any:
    """Return the VERIFIED entry author (entry.author / entry["author"]).

    This is the signature-authenticated identity, NOT the attacker-controllable
    payload["issued_by"]. Sovereignty checks must bind to this, not the payload."""
    author = getattr(entry, "author", None)
    if author is None and isinstance(entry, dict):
        author = entry.get("author")
    return author


def active_grants(
    entries: List[Mapping[str, Any]], self_did: Optional[str] = None
) -> Dict[GrantKey, Dict[str, Any]]:
    """Resolve the currently-active, SOVEREIGN grants from a journal entry list.

    Walks entries in order, recording every GRANT_ISSUE by grant_id, then
    dropping any grant_id that a later GRANT_REVOKE names. Returns
    {(scope, layer): grant_payload} for whatever survives — last GRANT_ISSUE
    wins if two issues ever named the same (scope, layer) (write-path
    validation via validate_issue is what actually prevents that).

    Sovereignty filter: a GRANT_ISSUE only confers real delegated authority
    when it was issued by the box itself (payload["issued_by"] == self_did).
    Grant ops federate like any other journal entry (export_entries/
    import_entries via dir_sync) — a mesh peer can author a well-formed,
    correctly-signed GRANT_ISSUE naming ITS OWN center as owner of some
    (scope, layer) and it will sync into every node's journal. Without this
    filter, config_router/owner/can_push would treat that foreign grant as
    local authority and apply the peer's config — a sovereignty break.

    When *self_did* is given, only grants with payload["issued_by"] ==
    self_did are kept; grants issued by anyone else are silently ignored
    (as if absent). When *self_did* is None (default), NO filter is applied
    — this is the pre-existing, unfiltered behavior, retained ONLY for
    low-level unit tests that construct journals without a notion of "self".
    Every real call site (config_router.route_config, api/main.py,
    sbx-centersctl) MUST pass self_did explicitly.
    """
    issued: Dict[str, Dict[str, Any]] = {}
    revoked_ids: set = set()

    for entry in entries:
        op = _op(entry)
        payload = _payload(entry)
        if op == "grant_issue":
            if self_did is not None and payload.get("issued_by") != self_did:
                continue
            issued[payload["grant_id"]] = payload
        elif op == "grant_revoke":
            revoked_ids.add(payload["grant_id"])

    result: Dict[GrantKey, Dict[str, Any]] = {}
    for grant_id, payload in issued.items():
        if grant_id in revoked_ids:
            continue
        result[(payload["scope"], payload["layer"])] = payload
    return result


def owner(
    entries: List[Mapping[str, Any]], scope: str, layer: str, self_did: Optional[str] = None
) -> Optional[str]:
    """Return the center_did that currently owns (scope, layer), or None.

    Only a grant issued by *self_did* counts as ownership — see
    active_grants()'s sovereignty filter docstring.
    """
    grant = active_grants(entries, self_did).get((scope, layer))
    return grant["center_did"] if grant else None


def can_push(
    entries: List[Mapping[str, Any]],
    center_did: str,
    scope: str,
    layer: str,
    self_did: Optional[str] = None,
) -> bool:
    """True iff *center_did* is the exact, exclusive, SELF-GRANTED owner of
    (scope, layer) — a grant issued by anyone other than *self_did* never
    makes this True. See active_grants()'s sovereignty filter docstring.
    """
    return owner(entries, scope, layer, self_did) == center_did


def validate_issue(
    entries: List[Mapping[str, Any]], scope: str, layer: str, self_did: Optional[str] = None
) -> Optional[str]:
    """Return a rejection reason for a prospective GRANT_ISSUE, or None if OK.

    Order matters (first hit wins):
      1. layer == "local"        -> "layer-local-not-delegatable"
      2. scope in NON_DELEGATABLE -> "scope-not-delegatable"
      3. (scope, layer) already owned -> "already-owned"

    The "already-owned" check is scoped to *self_did*'s own grants: a
    federated grant a mesh peer issued for itself does not block this box
    from issuing its own (sovereign) grant for the same (scope, layer) — see
    active_grants()'s sovereignty filter docstring. Callers issuing a real
    grant MUST pass self_did == the issuing box_did.
    """
    if layer == "local":
        return "layer-local-not-delegatable"
    if scope in NON_DELEGATABLE:
        return "scope-not-delegatable"
    if (scope, layer) in active_grants(entries, self_did):
        return "already-owned"
    return None

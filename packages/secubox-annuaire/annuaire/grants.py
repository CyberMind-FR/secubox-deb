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

Entries are consumed as plain mappings with an "op" key and a "payload"
key — the same shape both the raw journal-append call sites and
annuaire.log.Journal.iter_entries() rows expose. Op is a str Enum, so
comparing entry["op"] to the literal "grant_issue"/"grant_revoke" strings
works whether the caller passes Op members or bare strings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from .model import NON_DELEGATABLE

GrantKey = Tuple[str, str]


def active_grants(entries: List[Mapping[str, Any]]) -> Dict[GrantKey, Dict[str, Any]]:
    """Resolve the currently-active grants from a journal entry list.

    Walks entries in order, recording every GRANT_ISSUE by grant_id, then
    dropping any grant_id that a later GRANT_REVOKE names. Returns
    {(scope, layer): grant_payload} for whatever survives — last GRANT_ISSUE
    wins if two issues ever named the same (scope, layer) (write-path
    validation via validate_issue is what actually prevents that).
    """
    issued: Dict[str, Dict[str, Any]] = {}
    revoked_ids: set = set()

    for entry in entries:
        op = entry["op"]
        payload = entry["payload"]
        if op == "grant_issue":
            issued[payload["grant_id"]] = payload
        elif op == "grant_revoke":
            revoked_ids.add(payload["grant_id"])

    result: Dict[GrantKey, Dict[str, Any]] = {}
    for grant_id, payload in issued.items():
        if grant_id in revoked_ids:
            continue
        result[(payload["scope"], payload["layer"])] = payload
    return result


def owner(entries: List[Mapping[str, Any]], scope: str, layer: str) -> Optional[str]:
    """Return the center_did that currently owns (scope, layer), or None."""
    grant = active_grants(entries).get((scope, layer))
    return grant["center_did"] if grant else None


def can_push(entries: List[Mapping[str, Any]], center_did: str, scope: str, layer: str) -> bool:
    """True iff *center_did* is the exact, exclusive owner of (scope, layer)."""
    return owner(entries, scope, layer) == center_did


def validate_issue(entries: List[Mapping[str, Any]], scope: str, layer: str) -> Optional[str]:
    """Return a rejection reason for a prospective GRANT_ISSUE, or None if OK.

    Order matters (first hit wins):
      1. layer == "local"        -> "layer-local-not-delegatable"
      2. scope in NON_DELEGATABLE -> "scope-not-delegatable"
      3. (scope, layer) already owned -> "already-owned"
    """
    if layer == "local":
        return "layer-local-not-delegatable"
    if scope in NON_DELEGATABLE:
        return "scope-not-delegatable"
    if (scope, layer) in active_grants(entries):
        return "already-owned"
    return None

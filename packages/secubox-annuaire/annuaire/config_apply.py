# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: config_apply
Replica-side config distribution apply (gondwana P2, #768).

A primary node publishes a signed ConfigBlob for a scope (a module name) whose
payload carries the config file TEXT: ``{"format": "toml", "text": "<raw>"}``.
The blob replicates into every node's directory via mesh_sync. On a REPLICA,
this module applies the latest version to ``<target_dir>/<scope>.toml`` through
a CSPN 4R double-buffer:

    shadow  → write the new text to <target>.sbx-shadow
    validate→ BLAKE2b content_hash + TOML parseability (reject keeps active live)
    swap    → atomic os.replace(shadow, active)
    rollback→ the previous active is kept as <target>.sbx-rollback

Idempotent by ``version`` (state in applied-config.json) so a re-run is a no-op.
Single-writer is enforced by the caller: a node never applies a scope it is the
publisher of, and only scopes it has explicitly opted into (allowlist). Secrets
are never carried in a ConfigBlob.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import tomllib as _toml  # py3.11+
except ImportError:  # pragma: no cover
    import tomli as _toml  # type: ignore

from .config_compose import compose

# A scope becomes a filesystem path component (<target_dir>/<scope>.toml).
# It MUST NOT be able to escape target_dir — no '/', no '..', no empty
# string. This is the filesystem-boundary guard: it is checked BEFORE any
# Path is ever constructed from an untrusted scope, in both apply_blob
# (mesh-sourced ConfigBlob) and apply_composed (grant-routed layers).
_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _valid_scope(scope: Any) -> bool:
    """True iff *scope* is safe to use as a bare filename component."""
    return isinstance(scope, str) and bool(_SCOPE_RE.match(scope))


def blob_text(payload: Optional[Dict[str, Any]]) -> Optional[str]:
    """Extract the raw config text from a ConfigBlob payload, or None."""
    if not isinstance(payload, dict):
        return None
    text = payload.get("text")
    return text if isinstance(text, str) else None


def _blake2b_hex(text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), digest_size=32).hexdigest()


def load_state(state_path: str) -> Dict[str, Any]:
    try:
        return json.loads(Path(state_path).read_text())
    except (OSError, ValueError):
        return {}


def save_state(state_path: str, state: Dict[str, Any]) -> None:
    p = Path(state_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(p) + ".tmp"
    Path(tmp).write_text(json.dumps(state, indent=2, sort_keys=True))
    os.replace(tmp, str(p))


def apply_blob(
    blob: Dict[str, Any],
    target_dir: str,
    state: Dict[str, Any],
) -> Dict[str, Any]:
    """Apply one ConfigBlob to <target_dir>/<scope>.toml via the 4R buffer.

    Mutates `state` in place on success. Never raises; returns a status dict
    with status in {applied, skip, reject} and a reason. The active file is
    only ever replaced atomically after the shadow validates, so a bad blob
    leaves the live config untouched.
    """
    scope = blob.get("scope")
    version = blob.get("version")
    content_hash = blob.get("content_hash")
    if not scope or not isinstance(version, int) or not content_hash:
        return {"status": "reject", "scope": scope, "reason": "malformed-blob"}

    if not _valid_scope(scope):
        return {"status": "reject", "scope": scope, "reason": "invalid-scope"}

    cur = state.get(scope, {})
    if isinstance(cur.get("version"), int) and cur["version"] >= version:
        return {"status": "skip", "scope": scope, "reason": "version-not-newer"}

    text = blob_text(blob.get("payload"))
    if text is None:
        return {"status": "reject", "scope": scope, "reason": "no-inline-text"}

    if _blake2b_hex(text) != content_hash:
        return {"status": "reject", "scope": scope, "reason": "hash-mismatch"}

    try:
        _toml.loads(text)
    except Exception:
        return {"status": "reject", "scope": scope, "reason": "unparseable-toml"}

    active = Path(target_dir) / f"{scope}.toml"
    shadow = Path(str(active) + ".sbx-shadow")
    rollback = Path(str(active) + ".sbx-rollback")
    try:
        active.parent.mkdir(parents=True, exist_ok=True)
        shadow.write_text(text)
        if active.exists():
            rollback.write_text(active.read_text())  # R: keep the previous active
        os.replace(str(shadow), str(active))          # atomic swap
    except OSError as e:
        return {"status": "reject", "scope": scope, "reason": f"io:{e}"}

    state[scope] = {"version": version, "hash": content_hash}
    return {"status": "applied", "scope": scope, "version": version}


def apply_composed(
    scope: str,
    ordered_layer_texts: List[str],
    target_dir: str,
) -> Dict[str, Any]:
    """Compose a scope's layered TOML texts and apply via the same 4R buffer.

    ``ordered_layer_texts`` stacks baseline < override < local precedence
    (see ``config_compose.compose``). The composed text is re-validated as
    TOML, hashed with BLAKE2b (reusing ``_blake2b_hex``), and compared
    against the current active file's hash so an unchanged composition is a
    no-op (idempotent — avoids mesh_sync apply loops). On change, the SAME
    4R buffer as ``apply_blob`` writes it: shadow → rollback-copy of the
    previous active → atomic ``os.replace``. Never raises; returns a status
    dict with status in {applied, skip, reject}.
    """
    if not _valid_scope(scope):
        return {"status": "reject", "scope": scope, "reason": "invalid-scope"}

    try:
        text = compose(list(ordered_layer_texts))
        _toml.loads(text)  # re-validate the composed output before writing
    except Exception:
        return {"status": "reject", "scope": scope, "reason": "unparseable-toml"}

    h = _blake2b_hex(text)
    active = Path(target_dir) / f"{scope}.toml"
    if active.exists():
        try:
            current_text = active.read_text()
        except OSError:
            current_text = None
        if current_text is not None and _blake2b_hex(current_text) == h:
            return {"status": "skip", "scope": scope, "reason": "unchanged"}

    shadow = Path(str(active) + ".sbx-shadow")
    rollback = Path(str(active) + ".sbx-rollback")
    try:
        active.parent.mkdir(parents=True, exist_ok=True)
        shadow.write_text(text)
        if active.exists():
            rollback.write_text(active.read_text())  # R: keep the previous active
        os.replace(str(shadow), str(active))          # atomic swap
    except OSError as e:
        return {"status": "reject", "scope": scope, "reason": f"io:{e}"}

    return {"status": "applied", "scope": scope}


def apply_pending(
    configs: Iterable[Dict[str, Any]],
    *,
    allow_scopes: Iterable[str],
    self_did: Optional[str],
    target_dir: str,
    state_path: str,
) -> List[Dict[str, Any]]:
    """Apply every allowed ConfigBlob this node should consume.

    - `allow_scopes`: explicit opt-in (a replica never auto-applies arbitrary
      scopes). Use {"*"} to allow all.
    - `self_did`: a node never applies a scope it published itself (it is the
      single writer for that scope).
    Persists the version state once at the end. Returns per-scope results.
    """
    allow = set(allow_scopes)
    state = load_state(state_path)
    results: List[Dict[str, Any]] = []
    changed = False
    for blob in configs:
        scope = blob.get("scope")
        if not scope:
            continue
        if "*" not in allow and scope not in allow:
            results.append({"status": "skip", "scope": scope, "reason": "not-allowed"})
            continue
        if self_did and blob.get("publisher") == self_did:
            results.append({"status": "skip", "scope": scope, "reason": "self-published"})
            continue
        r = apply_blob(blob, target_dir, state)
        results.append(r)
        if r["status"] == "applied":
            changed = True
    if changed:
        save_state(state_path, state)
    return results

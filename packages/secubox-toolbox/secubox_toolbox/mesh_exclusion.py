# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: toolbox :: mesh-federate the MITM-exclusion lists (#806).

Publishes this node's LOCAL mutable exclusion lists (splice-learned, bypass-
dynamic, disabled) as a signed ConfigBlob under scope mitm-exclusion:<node_id>,
and (sync side, see the sync CLI) pulls every node's blob → union → the 3
federated files the R3 engine reads. Best-effort; never blocks.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
from pathlib import Path

LOCAL_SPLICE = Path("/var/lib/secubox/toolbox/splice-learned.txt")
LOCAL_BYPASS = Path("/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf")
LOCAL_DISABLED = Path("/var/lib/secubox/toolbox/mitm-filter-disabled.txt")
FED_SPLICE = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt")
FED_BYPASS = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt")
FED_DISABLED = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt")
ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"
SCOPE_PREFIX = "mitm-exclusion:"
FED_MAX = 2000


def _read_list(path: Path) -> list:
    """Non-comment, non-empty, inline-#-stripped, deduped, sorted, capped."""
    try:
        seen = []
        for ln in path.read_text(encoding="utf-8").splitlines():
            s = ln.split("#", 1)[0].strip()
            if s and s not in seen:
                seen.append(s)
        return sorted(seen)[:FED_MAX]
    except OSError:
        return []


def local_lists() -> dict:
    return {"splice": _read_list(LOCAL_SPLICE),
            "bypass": _read_list(LOCAL_BYPASS),
            "disabled": _read_list(LOCAL_DISABLED)}


def node_id() -> str:
    try:
        n = Path("/etc/secubox/node.id").read_text(encoding="utf-8").strip()
        if n:
            return n
    except OSError:
        pass
    return socket.gethostname()


def build_payload(nid: str, lists: dict) -> dict:
    return {"node": nid,
            "splice": lists.get("splice", [])[:FED_MAX],
            "bypass": lists.get("bypass", [])[:FED_MAX],
            "disabled": lists.get("disabled", [])[:FED_MAX]}


def content_hash(payload: dict) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.blake2b(text.encode("utf-8"), digest_size=32).hexdigest()


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, sock_path: str):
        super().__init__("localhost")
        self._sock_path = sock_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(self._sock_path)
        self.sock = s


def _annuaire(method: str, path: str, body: dict | None = None) -> dict | None:
    try:
        c = _UnixHTTP(ANNUAIRE_SOCK)
        hdr = {"Content-Type": "application/json"} if body else {}
        c.request(method, path, json.dumps(body) if body else None, hdr)
        r = c.getresponse()
        raw = r.read()
        c.close()
        if r.status >= 400:
            return None
        return json.loads(raw) if raw else {}
    except Exception:
        return None


def _version() -> int:
    import time
    return int(time.time())


def publish(payload: dict, priv_hex: str, did: str, nid: str) -> bool:
    """POST /config/publish under scope mitm-exclusion:<node_id>. Best-effort."""
    body = {"publisher_did": did, "publisher_priv_hex": priv_hex,
            "scope": SCOPE_PREFIX + nid, "version": _version(),
            "content_hash": content_hash(payload), "payload": payload}
    return _annuaire("POST", "/config/publish", body) is not None


def _atomic_write(path: Path, lines: list) -> bool:
    """Write sorted lines atomically; return True if content changed."""
    new = "\n".join(sorted(set(lines))[:FED_MAX])
    new = (new + "\n") if new else ""
    try:
        if path.exists() and path.read_text(encoding="utf-8") == new:
            return False
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(new, encoding="utf-8")
    os.replace(tmp, path)
    return True

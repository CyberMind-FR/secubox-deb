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
from typing import Optional

LOCAL_SPLICE = Path("/var/lib/secubox/toolbox/splice-learned.txt")
LOCAL_BYPASS = Path("/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf")
LOCAL_DISABLED = Path("/var/lib/secubox/toolbox/mitm-filter-disabled.txt")
FED_SPLICE = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-splice.txt")
FED_BYPASS = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-bypass.txt")
FED_DISABLED = Path("/var/lib/secubox/toolbox/mitm-exclusion-fed-disabled.txt")
ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"
SCOPE_PREFIX = "mitm-exclusion:"
FED_MAX = 2000

# annuaire's require_jwt only checks a valid HS256 signature + that the
# subject is an ENABLED user (user_store.is_enabled) — mirrors
# secubox-p2p/api/annuaire_client.py SERVICE_USER / _service_token() verbatim
# so the minted token is accepted the same way.
SERVICE_USER = os.environ.get("SBX_SERVICE_USER", "admin")


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


def _service_token() -> Optional[str]:
    """Mint a short service JWT so we can call annuaire's JWT-gated endpoints.

    Mirrors secubox-p2p/api/annuaire_client._service_token() exactly: annuaire
    and toolbox run on the same host and share the same secubox_core JWT
    secret, so a token minted here validates there. Best-effort — returns
    None if secubox_core is unavailable (e.g. in unit tests), in which case
    the caller sends no Authorization header.
    """
    try:
        from secubox_core.auth import create_token  # noqa: PLC0415
        return create_token(SERVICE_USER)
    except Exception:  # noqa: BLE001
        return None


def _annuaire(method: str, path: str, body: dict | None = None) -> dict | None:
    c = None
    try:
        c = _UnixHTTP(ANNUAIRE_SOCK)
        hdr = {"Content-Type": "application/json"} if body else {}
        token = _service_token()
        if token:
            hdr["Authorization"] = f"Bearer {token}"
        c.request(method, path, json.dumps(body) if body else None, hdr)
        r = c.getresponse()
        raw = r.read()
        if r.status >= 400:
            return None
        return json.loads(raw) if raw else {}
    except Exception:
        return None
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:
                pass


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


def _verify_blob(cfg: dict) -> dict | None:
    """Return the payload dict if the blob's content_hash matches its payload.
    Signature/author verification is done by the annuaire on ingest (only
    validly-signed blobs enter the journal that /config lists), so here we
    re-check the content_hash binds the payload we apply. Skip on mismatch."""
    payload = cfg.get("payload")
    if not isinstance(payload, dict):
        return None
    if cfg.get("content_hash") != content_hash(payload):
        return None
    return payload


def pull_blobs() -> list:
    """All current mitm-exclusion:* blob payloads (content-hash-verified)."""
    resp = _annuaire("GET", "/config")
    out = []
    for cfg in (resp or {}).get("configs", []):
        scope = cfg.get("scope") or ""
        if not scope.startswith(SCOPE_PREFIX):
            continue
        p = _verify_blob(cfg)
        if p is not None:
            out.append(p)
    return out


def union_blobs(blobs: list) -> dict:
    s, b, d = set(), set(), set()
    for p in blobs:
        for key, acc in (("splice", s), ("bypass", b), ("disabled", d)):
            v = p.get(key)
            if isinstance(v, list):
                acc.update(x for x in v if isinstance(x, str))
    return {"splice": sorted(s)[:FED_MAX], "bypass": sorted(b)[:FED_MAX],
            "disabled": sorted(d)[:FED_MAX]}


def sync() -> dict:
    u = union_blobs(pull_blobs())
    c1 = _atomic_write(FED_SPLICE, u["splice"])
    c2 = _atomic_write(FED_BYPASS, u["bypass"])
    c3 = _atomic_write(FED_DISABLED, u["disabled"])
    return {"splice": len(u["splice"]), "bypass": len(u["bypass"]),
            "disabled": len(u["disabled"]), "changed": c1 or c2 or c3}

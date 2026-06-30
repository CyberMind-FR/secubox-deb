# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: mesh_sync
Directory replication over the gondwana wg-mesh (gondwana P1, #768).

The sync loop runs IN-PROCESS in the annuaire service (the journal owner) so it
needs no JWT and cannot race a second writer. secubox-p2p remains the owner of
the peer list (its wg_mesh.json); this module only reads it. For each mesh peer
it pulls the peer's public /log/export and merges via verbs.import_entries
(which verifies every entry's signature and the self-certifying binding before
appending). Pull-only, eventually consistent, last-writer-wins at the state
layer — convergent regardless of order.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

DEFAULT_PEERS_PATH = "/var/lib/secubox/p2p/wg_mesh.json"
DEFAULT_NGINX_PORT = 9080  # nginx listens on 0.0.0.0:9080 → reachable on the mesh IP


def read_mesh_peers(path: str = DEFAULT_PEERS_PATH) -> List[Dict[str, str]]:
    """Return [{mesh_ip, name}] from secubox-p2p's wg_mesh.json (own peers only).

    Missing / unreadable / malformed file → [] (the sync simply no-ops). The
    local node itself is never in this list (wg_mesh.json holds peers, not self).
    """
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    peers: List[Dict[str, str]] = []
    for p in data.get("peers", []):
        ip = p.get("mesh_ip") or (p.get("allowed_ips", "").split("/")[0] or "")
        if ip:
            peers.append({"mesh_ip": ip, "name": p.get("name", "")})
    return peers


def http_fetch(url: str, timeout: int = 5) -> List[Dict[str, Any]]:
    """Fetch a peer's /log/export and return its `entries` list (production fetcher)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (mesh-local)
        data = json.loads(resp.read())
    return data.get("entries", []) if isinstance(data, dict) else []


def sync_once(
    journal: Any,
    peers: List[Dict[str, str]],
    fetch: Callable[[str], List[Dict[str, Any]]] = http_fetch,
    port: int = DEFAULT_NGINX_PORT,
) -> Dict[str, int]:
    """Pull /log/export from each peer and merge. Never raises — an unreachable
    or malformed peer is counted in `errors` and skipped. `fetch` is injectable
    for testing. Returns aggregate {peers, ingested, skipped, rejected, errors}.
    """
    from .verbs import import_entries  # noqa: PLC0415

    totals = {"peers": 0, "ingested": 0, "skipped": 0, "rejected": 0, "errors": 0}
    for peer in peers:
        ip = peer.get("mesh_ip")
        if not ip:
            continue
        url = f"http://{ip}:{port}/api/v1/annuaire/log/export"
        try:
            entries = fetch(url)
        except Exception:
            totals["errors"] += 1
            continue
        res = import_entries(journal, entries or [])
        totals["peers"] += 1
        totals["ingested"] += res["ingested"]
        totals["skipped"] += res["skipped"]
        totals["rejected"] += res["rejected"]
    return totals

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
# The dedicated Gondwana mesh listener (#766) binds <wg-mesh-ip>:8799, allow
# 10.10.0.0/24 + deny all, and serves only the signed read paths
# (/services, /log/export). We pull /log/export from it — never the main :9080.
DEFAULT_MESH_PORT = 8799


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


DEFAULT_MESH_NETWORK = "10.10.0.0/24"


def reseau_maillage(path: str = DEFAULT_PEERS_PATH) -> str:
    """Réseau du maillage (champ « network » de wg_mesh.json), 10.10.0.0/24 à défaut. Jamais d'exception."""
    try:
        return str(json.loads(Path(path).read_text()).get("network") or DEFAULT_MESH_NETWORK)
    except (OSError, ValueError, AttributeError):
        return DEFAULT_MESH_NETWORK


def noeuds_du_repertoire(journal: Any) -> List[Dict[str, Any]]:
    """Fiches de nœud du répertoire (dernière fiche auto-signée par did) ; [] si le journal ne se lit pas."""
    try:
        from .verbs import _get_nodes  # noqa: PLC0415
        return _get_nodes(journal)
    except Exception:  # noqa: BLE001 — la découverte est un plus, jamais une cause d'échec
        return []


def completer_pairs(
    wg_peers: List[Dict[str, str]],
    noeuds: List[Dict[str, Any]],
    soi: str = "",
    reseau: str = DEFAULT_MESH_NETWORK,
) -> List[Dict[str, str]]:
    """Pairs de synchro = pairs WireGuard + nœuds du répertoire (#2569), sans doublon et sans soi-même.

    Sur une étoile, un satellite n'a que le maître comme pair WireGuard ; les autres satellites sont joignables par le maître (qui transfère le
    réseau du maillage), et leur adresse est signée dans leur fiche de nœud. Une fiche est auto-déclarée : seule une adresse INTERNE au réseau
    du maillage est suivie, une autre (ou invalide) est ignorée."""
    import ipaddress  # noqa: PLC0415
    try:
        net = ipaddress.ip_network(reseau, strict=False)
    except ValueError:
        net = ipaddress.ip_network(DEFAULT_MESH_NETWORK)
    pairs = list(wg_peers)
    connus = {p.get("mesh_ip") for p in pairs} | ({soi} if soi else set())
    for n in noeuds:
        ip = str(n.get("mesh_ip") or "")
        try:
            ok = bool(ip) and ipaddress.ip_address(ip) in net
        except ValueError:
            ok = False
        if ok and ip not in connus:
            pairs.append({"mesh_ip": ip, "name": str(n.get("boxname") or "")})
            connus.add(ip)
    return pairs


def read_self_meta(
    wg_path: str = DEFAULT_PEERS_PATH,
    node_id_path: str = "/var/lib/secubox/p2p/node.id",
    hostname: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Build this node's NodeRecord fields from secubox-p2p's local state.

    Returns {node_id, boxname, pubkey_wg, mesh_ip, ddns, endpoint} or None when
    the mesh isn't provisioned (no wg_mesh.json / no self address) — the node
    then simply doesn't publish a record. boxname falls back to the DDNS label,
    then the hostname. We don't know our own public IP here, so reachability is
    name-based via ddns and endpoint stays None.
    """
    try:
        d = json.loads(Path(wg_path).read_text())
    except (OSError, ValueError):
        return None
    addr = (d.get("address") or "").split("/")[0]
    if not addr:
        return None
    ddns = d.get("ddns") or ""
    if hostname is None:
        import socket  # noqa: PLC0415
        hostname = socket.gethostname()
    boxname = (ddns.split(".")[0] if ddns else "") or hostname
    try:
        node_id = Path(node_id_path).read_text().strip()
    except OSError:
        node_id = f"sb-{boxname}"
    return {
        "node_id": node_id,
        "boxname": boxname,
        "pubkey_wg": d.get("public_key") or "",
        "mesh_ip": addr,
        "ddns": ddns or f"{boxname}.secubox.in",
        "endpoint": None,
    }


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
    port: int = DEFAULT_MESH_PORT,
    ops: Optional[str] = None,
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
        url = f"http://{ip}:{port}/api/v1/annuaire/log/export" + (f"?ops={ops}" if ops else "")
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


def http_json(url: str, timeout: int = 5) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (mesh-local)
        data = json.loads(resp.read(65536))
    return data if isinstance(data, dict) else {}


def relever_droits(peers: List[Dict[str, str]], fetch: Callable[[str], Dict[str, Any]] = http_json, chemin: Any = None,
                   port: int = DEFAULT_MESH_PORT) -> bool:
    """#3305 : demande à chaque pair les droits de CETTE box (`droits/self`) ; la première réponse d'un pair qui a une politique (le maître)
    est gardée. Vrai si une politique a répondu. Jamais d'exception."""
    from . import droits as D  # noqa: PLC0415
    for peer in peers:
        ip = peer.get("mesh_ip")
        if not ip:
            continue
        try:
            rep = fetch(f"http://{ip}:{port}/api/v1/annuaire/droits/self")
        except Exception:  # noqa: BLE001 — pair injoignable ou ancien (404) : le suivant
            continue
        if isinstance(rep, dict) and rep.get("politique") is True:
            try:
                D.noter_droits_self(rep, chemin or D.SELF_DEFAUT)
            except OSError:
                return False
            return True
    return False

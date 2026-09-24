# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: mesh
Pure mesh logic — no FastAPI, no privilege. Imported by api/main.py (state
endpoints, runs as user secubox) and by sbx-mesh-up (root provisioner).
"""
from __future__ import annotations
import base64
import ipaddress
import pathlib
import re
import tomllib

MESH_INTERFACE = "wg-mesh"
MESH_PORT = 51822
MESH_NETWORK = "10.10.0.0/24"

# Reserved subnets the mesh must never overlap (name -> CIDR).
RESERVED_SUBNETS = {
    "br-lxc": "10.100.0.0/24",
    "eye-br0": "10.55.0.0/24",
    "lxcbr0": "10.0.3.0/24",
    "wg-toolbox": "10.99.0.0/24",
}


def subnet_overlap(network: str) -> str | None:
    """Return the name of the first RESERVED_SUBNETS entry that overlaps
    `network`, or None if `network` is clear."""
    net = ipaddress.ip_network(network, strict=False)
    for name, cidr in RESERVED_SUBNETS.items():
        if net.overlaps(ipaddress.ip_network(cidr, strict=False)):
            return name
    return None


DHT_DEFAULTS = {
    "enabled": False,
    "port": 51823,
    "bootstrap": [],
    "announce": False,
    "announce_interval": 900,
    "rps": 50,
}

FEDERATION_DEFAULTS = {
    "health_checks": False,
    "interval": 30,
    "probe_timeout": 5,
    "max_concurrency": 20,
    "fail_threshold": 3,
}

MASTERLINK_DEFAULTS = {
    "enabled": False,
    "role_preference": "auto",
    "priority": 100,
    "heartbeat_interval": 5,
    "election_timeout": 15,
    "port": 51824,
    "peer_addrs": [],
}


def load_p2p_config(path: pathlib.Path) -> dict:
    """Read /etc/secubox/p2p.toml, with defaults.

    Returns a dict with the legacy [wireguard]-derived keys at the top level
    (unchanged, for backward compatibility) plus a `dht` sub-dict built from
    the [dht] section (Issue #774 Task 9) and a `federation` sub-dict built
    from the [federation] section (Issue #774 Task 13)."""
    defaults = {
        "interface": MESH_INTERFACE,
        "listen_port": MESH_PORT,
        "network": MESH_NETWORK,
        "role": "satellite",
        "master_endpoint": None,
    }
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f) or {}
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        doc = {}
    wg = doc.get("wireguard", {}) or {}
    out = dict(defaults)
    for k in defaults:
        if wg.get(k) is not None:
            out[k] = wg[k]

    dht = doc.get("dht", {}) or {}
    out_dht = dict(DHT_DEFAULTS)
    for k in DHT_DEFAULTS:
        if dht.get(k) is not None:
            out_dht[k] = dht[k]
    out["dht"] = out_dht

    federation = doc.get("federation", {}) or {}
    out_federation = dict(FEDERATION_DEFAULTS)
    for k in FEDERATION_DEFAULTS:
        if federation.get(k) is not None:
            out_federation[k] = federation[k]
    out["federation"] = out_federation

    masterlink = doc.get("masterlink", {}) or {}
    out_masterlink = dict(MASTERLINK_DEFAULTS)
    for k in MASTERLINK_DEFAULTS:
        if masterlink.get(k) is not None:
            out_masterlink[k] = masterlink[k]
    out["masterlink"] = out_masterlink
    return out


def allocate_mesh_ip(network: str, taken: list[str]) -> str:
    """Lowest free host >= .2 in `network` (.1 reserved for master)."""
    taken_set = {t.split("/")[0] for t in taken}
    net = ipaddress.ip_network(network, strict=False)
    base = int(net.network_address)
    for off in range(2, net.num_addresses - 1):
        cand = str(ipaddress.ip_address(base + off))
        if cand not in taken_set:
            return cand
    raise RuntimeError(f"mesh address pool {network} exhausted")


def parse_wg_conf(text: str) -> dict:
    """Extract Interface fields from a wg-quick config (first [Interface])."""
    out = {"private_key": None, "address": None, "listen_port": None}
    in_iface = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_iface = line.lower() == "[interface]"
            continue
        if not in_iface or "=" not in line:
            continue
        key, val = (p.strip() for p in line.split("=", 1))
        kl = key.lower()
        if kl == "privatekey":
            out["private_key"] = val
        elif kl == "address":
            out["address"] = val
        elif kl == "listenport":
            out["listen_port"] = int(val)
    return out


def _une_ligne(valeur) -> str:
    """Refuse toute valeur qui sortirait de sa ligne dans le fichier rendu.

    Ce fichier est lu par wg-quick EN ROOT, qui exécute ses directives
    `PostUp`. Un endpoint contenant un saut de ligne y ferait entrer une
    commande arbitraire (#1360). On refuse plutôt que de nettoyer : une valeur
    qui a besoin d'être nettoyée n'est pas une adresse.
    """
    v = str(valeur)
    if any(c in v for c in "\r\n\x00"):
        raise ValueError("refusing multi-line value in wg-quick config")
    return v


def render_wg_conf(state: dict) -> str:
    """Render a wg-quick config from mesh state."""
    lines = [
        "# Managed by secubox-p2p (sbx-mesh-up) — do not edit by hand.",
        "[Interface]",
        f"PrivateKey = {_une_ligne(state['private_key'])}",
        f"Address = {_une_ligne(state['address'])}",
        f"ListenPort = {int(state.get('listen_port', MESH_PORT))}",
    ]
    for peer in state.get("peers", []):
        lines += ["", "[Peer]", f"PublicKey = {_une_ligne(peer['public_key'])}"]
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {_une_ligne(peer['endpoint'])}")
        lines.append(f"AllowedIPs = {_une_ligne(peer.get('allowed_ips', MESH_NETWORK))}")
        lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"


def adopt_state(state: dict, existing_conf_text: str | None) -> dict:
    """Import the live wg-mesh private key so the public key is preserved.
    Never overwrites a key already present in state."""
    if state.get("private_key"):
        return state
    if not existing_conf_text:
        return state
    parsed = parse_wg_conf(existing_conf_text)
    if parsed["private_key"]:
        state["private_key"] = parsed["private_key"]
        if not state.get("address") and parsed["address"]:
            state["address"] = parsed["address"]
        if parsed["listen_port"]:
            state["listen_port"] = parsed["listen_port"]
    return state


def ddns_name(hostname: str, domain: str = "secubox.in") -> str:
    """Return DDNS-safe hostname: lowercased, non-[a-z0-9-] replaced by -, .domain appended."""
    slug = re.sub(r"[^a-z0-9-]", "-", hostname.lower())
    slug = slug[:63] if slug else "node"
    return f"{slug}.{domain}"


def _host_ip(allowed_ips: str) -> str:
    """Return the single host IP from an allowed-ips value, else "".

    A peer's mesh address is recoverable only when its allowed-ips is a /32
    host route (the master's view of a spoke). A /24 (a spoke's route to the
    hub) is not a host address, so we return "" and rely on an explicit
    mesh_ip field instead.
    """
    first = (allowed_ips or "").split(",")[0].strip()
    if first.endswith("/32"):
        return first.split("/")[0]
    return ""


# ── ÉCHANGE DE CLÉS À LA JONCTION (#1360) ────────────────────────────────────
#
# L'enrôlement « réussissait » sans jamais monter de tunnel : la requête de
# jonction ne portait aucune clé WireGuard, et l'approbation écrivait dans le
# registre hérité `peers.json` — jamais dans `wg_mesh.json`, qui est la source
# de vérité du transport. Deux appliances pouvaient donc se dire « jointes »
# indéfiniment sans qu'un seul paquet passe entre elles.

# Où le provisionneur root dépose les dernières poignées de main. Le service
# tourne sous `secubox` et ne peut pas les lire lui-même (netlink WireGuard
# exige CAP_NET_ADMIN) : un minuteur root les écrit, le service les LIT.
HANDSHAKES_PATH = pathlib.Path("/run/secubox/p2p/wg-mesh-handshakes.json")

# Au-delà, un pair n'est plus considéré en ligne. WireGuard renégocie toutes les
# deux minutes tant que du trafic passe, et le keepalive de 25 s en génère : un
# pair vivant ne dépasse jamais ~2 min 25. Trois minutes laissent une marge
# sans masquer une vraie coupure.
LIVENESS_MAX_AGE = 180

# Au-delà, le FICHIER lui-même est trop vieux pour qu'on s'y fie : le minuteur
# qui l'écrit est arrêté. Dire alors « hors ligne » accuserait les pairs d'une
# panne qui est la nôtre.
HANDSHAKES_MAX_STALENESS = 120


def valid_wg_key(key) -> bool:
    """Une clé WireGuard est 32 octets en base64 standard (44 caractères).

    Validée AVANT d'entrer dans l'état : elle finit dans un fichier de
    configuration rendu, et une valeur arbitraire y injecterait des lignes.
    """
    if not isinstance(key, str) or len(key) != 44 or not key.endswith("="):
        return False
    try:
        return len(base64.b64decode(key, validate=True)) == 32
    except Exception:
        return False


def taken_mesh_ips(wg_state: dict, legacy_peers: list, requests: list) -> list:
    """Toutes les adresses déjà engagées, QUELLE QUE SOIT leur source.

    L'allocateur ne regardait que `peers.json`. Mesuré sur gk2 : la VM de test
    a reçu 10.10.0.2 — l'adresse de c3box dans `wg_mesh.json`. Si la jonction
    avait monté le tunnel, elle aurait détourné la route d'un autre pair. Une
    adresse est prise dès qu'UNE des trois sources la mentionne.
    """
    taken = []
    own = (wg_state.get("address") or "").split("/")[0]
    if own:
        taken.append(own)
    for p in wg_state.get("peers", []):
        ip = p.get("mesh_ip") or _host_ip(p.get("allowed_ips", ""))
        if ip:
            taken.append(ip)
    for p in legacy_peers or []:
        if p.get("mesh_ip"):
            taken.append(p["mesh_ip"])
    for r in requests or []:
        if r.get("mesh_ip") and r.get("status") in ("pending", "approved"):
            taken.append(r["mesh_ip"])
    return taken


def upsert_mesh_peer(state: dict, peer: dict) -> dict:
    """Ajoute un pair à l'état WireGuard, ou remplace celui qu'il était.

    Un nœud qui se réenrôle (réinstallation, nouvelle clé) doit REMPLACER son
    ancienne entrée, pas s'y ajouter : deux clés pour une même empreinte
    laisseraient une entrée morte que plus rien ne retire.

    Refuse une adresse déjà tenue par une AUTRE clé : WireGuard déplacerait la
    route en silence vers le dernier arrivé, et l'ancien pair deviendrait
    injoignable sans qu'aucune erreur ne l'annonce.
    """
    peers = [p for p in state.get("peers", [])
             if not (peer.get("fingerprint") and p.get("fingerprint") == peer["fingerprint"])
             and p.get("public_key") != peer["public_key"]]
    ip = peer.get("mesh_ip")
    for p in peers:
        if ip and (p.get("mesh_ip") or _host_ip(p.get("allowed_ips", ""))) == ip:
            raise ValueError(f"mesh address {ip} already held by another key")
    peers.append(peer)
    state["peers"] = peers
    return state


def load_handshakes(path: pathlib.Path = None, now: float = None):
    """Les poignées de main écrites par le minuteur root, ou None si on ne sait pas.

    None n'est pas « personne en ligne » : c'est « la mesure manque ». Les deux
    se distinguent à l'affichage, sinon une panne du minuteur ressemblerait à
    une panne de tous les pairs.
    """
    import json
    import time
    path = path or HANDSHAKES_PATH
    now = time.time() if now is None else now
    try:
        doc = json.loads(pathlib.Path(path).read_text())
    except Exception:
        return None
    if now - float(doc.get("written_at", 0)) > HANDSHAKES_MAX_STALENESS:
        return None
    return {k: int(v) for k, v in (doc.get("handshakes") or {}).items()}


def peer_liveness(handshakes, public_key: str, now: float) -> str:
    """« online », « offline » ou « unknown » — jamais une supposition."""
    if handshakes is None:
        return "unknown"
    ts = handshakes.get(public_key, 0)
    if ts <= 0:
        return "offline"          # jamais de poignée de main
    return "online" if now - ts <= LIVENESS_MAX_AGE else "offline"


def peer_nodes(state: dict, handshakes=None, now: float = None) -> list:
    """Map wg_mesh.json peers to app-layer node dicts for the /peers + /status
    API and the P2P web UI. The mesh transport (wg_mesh.json) is the source of
    truth; the legacy peers.json registry is unused by the mesh view.

    LE STATUT EST MESURÉ, PLUS SUPPOSÉ (#1360). Il valait « online » en dur, avec
    un commentaire qui renvoyait la sonde de vivacité à plus tard. Résultat
    mesuré sur gk2 : l'API annonçait deux pairs en ligne — deux pairs qui
    n'avaient JAMAIS établi de poignée de main, dont une machine éteinte — et
    ignorait le seul qui était réellement connecté. Un compteur qui ne peut pas
    descendre ne prouve rien, et un test du mesh qui s'y fie ne peut pas
    échouer.
    """
    import time
    now = time.time() if now is None else now
    out = []
    for p in state.get("peers", []):
        ip = p.get("mesh_ip") or _host_ip(p.get("allowed_ips", ""))
        name = p.get("name") or ip or (p.get("public_key", "")[:12] or "peer")
        pk = p.get("public_key", "")
        ts = (handshakes or {}).get(pk, 0) if handshakes is not None else None
        out.append({
            "id": name,
            "name": name,
            "address": ip,
            "public_key": pk,
            "status": peer_liveness(handshakes, pk, now),
            "latency": None,
            "last_seen": (int(ts) if ts else None),
        })
    return out

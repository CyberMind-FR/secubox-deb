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


def render_wg_conf(state: dict) -> str:
    """Render a wg-quick config from mesh state."""
    lines = [
        "# Managed by secubox-p2p (sbx-mesh-up) — do not edit by hand.",
        "[Interface]",
        f"PrivateKey = {state['private_key']}",
        f"Address = {state['address']}",
        f"ListenPort = {state.get('listen_port', MESH_PORT)}",
    ]
    for peer in state.get("peers", []):
        lines += ["", "[Peer]", f"PublicKey = {peer['public_key']}"]
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append(f"AllowedIPs = {peer.get('allowed_ips', MESH_NETWORK)}")
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


def peer_nodes(state: dict) -> list:
    """Map wg_mesh.json peers to app-layer node dicts for the /peers + /status
    API and the P2P web UI. The mesh transport (wg_mesh.json) is the source of
    truth; the legacy peers.json registry is unused by the mesh view.

    Each node carries the fields the web UI renders: id, name, address,
    public_key, status, latency, last_seen. `status` is reported "online"
    (the unprivileged service cannot read wg handshakes to probe liveness;
    a privileged liveness probe is future work).
    """
    out = []
    for p in state.get("peers", []):
        ip = p.get("mesh_ip") or _host_ip(p.get("allowed_ips", ""))
        name = p.get("name") or ip or (p.get("public_key", "")[:12] or "peer")
        out.append({
            "id": name,
            "name": name,
            "address": ip,
            "public_key": p.get("public_key", ""),
            "status": "online",
            "latency": None,
            "last_seen": None,
        })
    return out

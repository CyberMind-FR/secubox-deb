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


def load_p2p_config(path: pathlib.Path) -> dict:
    """Read the [wireguard] section of /etc/secubox/p2p.toml, with defaults."""
    defaults = {
        "interface": MESH_INTERFACE,
        "listen_port": MESH_PORT,
        "network": MESH_NETWORK,
        "role": "satellite",
        "master_endpoint": None,
    }
    try:
        with open(path, "rb") as f:
            wg = (tomllib.load(f) or {}).get("wireguard", {}) or {}
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        wg = {}
    out = dict(defaults)
    for k in defaults:
        if wg.get(k) is not None:
            out[k] = wg[k]
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
    return f"{slug}.{domain}"

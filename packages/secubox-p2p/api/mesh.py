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

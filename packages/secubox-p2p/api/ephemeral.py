# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: p2p.ephemeral — pure registry + guards for session-scoped
WireGuard peers on the wg-ephemeral iface. No wg/ip calls here (secubox-p2pctl
does those); this module is the fail-closed bookkeeping the CLI and the sweep
timer share. Ephemeral peers NEVER enter the persistent gondwana mesh state.
"""
from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Dict, List, Tuple

EPHEMERAL_RANGE = "10.11.0.0/24"
EPHEMERAL_IFACE = "wg-ephemeral"
BOX_ADDR = "10.11.0.1/24"
LISTEN_PORT = 51825
REGISTRY_PATH = "/var/lib/secubox/p2p/ephemeral.json"
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
_EMPTY = {"boot_id": None, "peers": []}


def in_range(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    net = ipaddress.ip_network(EPHEMERAL_RANGE)
    return addr in net and addr != net.network_address and addr != net.broadcast_address


def host_of(allowed_ip: str) -> str:
    if not allowed_ip.endswith("/32"):
        raise ValueError(f"expected a /32, got {allowed_ip!r}")
    host = allowed_ip[:-3]
    ipaddress.ip_address(host)  # validate; raises ValueError
    return host


def load(path: str = REGISTRY_PATH) -> Dict[str, Any]:
    try:
        with open(path) as fh:
            reg = json.load(fh)
        if not isinstance(reg, dict) or "peers" not in reg:
            return dict(_EMPTY)
        reg.setdefault("boot_id", None)
        reg.setdefault("peers", [])
        return reg
    except (OSError, ValueError):
        return dict(_EMPTY)


def save(reg: Dict[str, Any], path: str = REGISTRY_PATH) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(reg, fh)
    os.replace(tmp, path)


def record_peer(reg, pubkey, ip, did, endpoint, expires_ts) -> Dict[str, Any]:
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("ip") != ip]
    reg["peers"].append({"pubkey": pubkey, "ip": ip, "did": did,
                         "endpoint": endpoint, "expires_ts": expires_ts})
    return reg


def remove_by_ip(reg, ip) -> List[Dict[str, Any]]:
    removed = [p for p in reg.get("peers", []) if p.get("ip") == ip]
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("ip") != ip]
    return removed


def remove_by_did(reg, did) -> List[Dict[str, Any]]:
    removed = [p for p in reg.get("peers", []) if p.get("did") == did]
    reg["peers"] = [p for p in reg.get("peers", []) if p.get("did") != did]
    return removed


def expired(reg, now_ts: str) -> List[Dict[str, Any]]:
    out = []
    for p in reg.get("peers", []):
        ts = p.get("expires_ts") or ""
        # fail-closed: empty/malformed -> treat as expired (never sticky).
        if not ts or len(ts) != 20 or not ts.endswith("Z"):
            out.append(p)
            continue
        if ts <= now_ts:  # RFC3339 Z is lexicographically ordered
            out.append(p)
    return out


def boot_flush(reg, current_boot_id: str) -> Tuple[Dict[str, Any], bool]:
    if reg.get("boot_id") != current_boot_id:
        return {"boot_id": current_boot_id, "peers": []}, True
    return reg, False

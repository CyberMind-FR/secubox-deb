# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Phase 6 (#496) — WireGuard profile generation for R3 ToolBoX clients.

Generates :
  - a fresh client keypair per request
  - a .conf file (WireGuard standard format) ready to import via wg-quick
  - a .mobileconfig wrapper (iOS one-tap install)
  - registers the client peer with the server's wg-toolbox interface
  - returns a payload suitable for QR code encoding

The server's WG keypair + listen port are static (provisioned at install).
Each client gets a private subnet IP from 10.99.1.0/24 (separate from
the captive 10.99.0.0/24).
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

log = logging.getLogger("secubox.toolbox.wg")

# Server-side WG config — provisioned by secubox-toolbox-wg-provision.
SERVER_CONF = Path("/etc/secubox/toolbox/wg/server.conf")
SERVER_PUBKEY = Path("/etc/secubox/toolbox/wg/server.pubkey")
PEERS_DB = Path("/var/lib/secubox/toolbox/wg-peers.json")

# Client subnet — distinct from captive 10.99.0.0/24
CLIENT_SUBNET_BASE = "10.99.1"
WG_PORT = 51820
WG_ENDPOINT = "kbin.gk2.net"
WG_INTERFACE = "wg-toolbox"

# CA cert to bundle in the profile (so client trusts mitm's leaf certs)
CA_PEM_PATH = Path("/etc/secubox/toolbox/ca-wg/ca.pem")


def _wg_genkey() -> str:
    return subprocess.check_output(["wg", "genkey"], text=True).strip()


def _wg_pubkey(privkey: str) -> str:
    return subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True,
                           text=True, check=True).stdout.strip()


def _load_peers() -> dict:
    if not PEERS_DB.exists():
        return {"next_ip_octet": 2, "peers": {}}
    try:
        return json.loads(PEERS_DB.read_text())
    except Exception:
        return {"next_ip_octet": 2, "peers": {}}


def _save_peers(d: dict) -> None:
    PEERS_DB.parent.mkdir(parents=True, exist_ok=True)
    PEERS_DB.write_text(json.dumps(d, indent=2))


def _server_pubkey() -> str:
    if SERVER_PUBKEY.exists():
        return SERVER_PUBKEY.read_text().strip()
    return "<server-not-provisioned>"


def _ca_pem() -> str:
    if CA_PEM_PATH.exists():
        return CA_PEM_PATH.read_text()
    return ""


def generate_client_profile(client_label: str | None = None) -> dict:
    """Generate a new WG client profile.

    Returns :
      {
        client_privkey, client_pubkey, client_ip,
        server_pubkey, endpoint, dns,
        conf_text,        # standard .conf for wg-quick
        ca_pem,           # CA root bundled
        mobileconfig,     # iOS .mobileconfig wrapper (TODO Phase 6.B)
      }
    """
    priv = _wg_genkey()
    pub = _wg_pubkey(priv)
    server_pub = _server_pubkey()

    # Allocate next IP from peer DB
    peers = _load_peers()
    octet = peers.get("next_ip_octet", 2)
    client_ip = f"{CLIENT_SUBNET_BASE}.{octet}"
    peers["next_ip_octet"] = (octet + 1) if octet < 254 else 2
    peers.setdefault("peers", {})[pub] = {
        "ip": client_ip,
        "label": client_label or "anonymous",
        "created_at": int(_now_ts()),
    }
    _save_peers(peers)

    # Register the peer with the running wg interface
    try:
        subprocess.run([
            "wg", "set", WG_INTERFACE,
            "peer", pub,
            "allowed-ips", f"{client_ip}/32",
        ], check=False, timeout=2)
    except Exception as e:
        log.warning("wg peer registration failed (interface down?): %s", e)

    # Compose the .conf payload
    conf_text = (
        f"[Interface]\n"
        f"PrivateKey = {priv}\n"
        f"Address = {client_ip}/32\n"
        f"DNS = 10.99.0.1\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {WG_ENDPOINT}:{WG_PORT}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )

    return {
        "client_privkey": priv,
        "client_pubkey": pub,
        "client_ip": client_ip,
        "server_pubkey": server_pub,
        "endpoint": f"{WG_ENDPOINT}:{WG_PORT}",
        "dns": "10.99.0.1",
        "conf_text": conf_text,
        "ca_pem": _ca_pem(),
    }


def revoke_client(client_pubkey: str) -> bool:
    """Remove a client peer from the WG interface + peer DB."""
    peers = _load_peers()
    if client_pubkey in (peers.get("peers") or {}):
        del peers["peers"][client_pubkey]
        _save_peers(peers)
    try:
        subprocess.run([
            "wg", "set", WG_INTERFACE,
            "peer", client_pubkey,
            "remove",
        ], check=False, timeout=2)
        return True
    except Exception as e:
        log.warning("wg peer revoke failed: %s", e)
        return False


def _now_ts() -> float:
    import time
    return time.time()

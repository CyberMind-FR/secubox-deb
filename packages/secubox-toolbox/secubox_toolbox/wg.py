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
WG_ENDPOINT = "kbin.gk2.secubox.in"  # Gandi-managed, A → 82.67.100.75 (gk2 pub IP)
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
        # Phase 7 (#498) — was 10.99.0.1 (captive-AP IP) ; if the wlan AP is
        # down the iPhone gets ICMP unreachable. Use the wg server IP which
        # is always up while the tunnel is.
        f"DNS = 10.99.1.1\n"
        f"\n"
        f"[Peer]\n"
        f"PublicKey = {server_pub}\n"
        f"Endpoint = {WG_ENDPOINT}:{WG_PORT}\n"
        f"AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"PersistentKeepalive = 25\n"
    )

    # Phase 7 (#498) — NetworkManager keyfile alongside the standard
    # wg-quick .conf. The Cosmic / GNOME Network UI imports .conf files
    # via nmcli but stores the private key as an "agent-owned" secret by
    # default (private-key-flags=1) — which means nmcli refuses to bring
    # the tunnel up without --ask. A native .nmconnection keyfile drops
    # straight into /etc/NetworkManager/system-connections/ with the
    # right system-owned flag and lets the operator click "Connect".
    # Phase 7 follow-up (#498) — connection NAME must be stable + readable.
    # Previously used `client_label` which is the raw User-Agent, so users
    # ended up with NetworkManager connections called
    # "Mozilla/5.0 (X11; Linux x86_64; rv:151.0) Gecko/20100101 Firefox/151.0".
    # Use a tidy ID based on the assigned tunnel IP — last octet keeps it
    # short (village3b-r3-42) and distinct per peer.
    last_octet = client_ip.rsplit(".", 1)[-1]
    nm_text = _nm_keyfile(
        conn_id=f"village3b-r3-{last_octet}",
        priv=priv,
        client_ip=client_ip,
        server_pub=server_pub,
    )

    return {
        "client_privkey": priv,
        "client_pubkey": pub,
        "client_ip": client_ip,
        "server_pubkey": server_pub,
        "endpoint": f"{WG_ENDPOINT}:{WG_PORT}",
        "dns": "10.99.1.1",
        "conf_text": conf_text,
        "nm_text": nm_text,
        "ca_pem": _ca_pem(),
    }


def _nm_keyfile(*, conn_id: str, priv: str, client_ip: str, server_pub: str) -> str:
    """Build a NetworkManager keyfile (.nmconnection) for the same peer.

    Dropped into /etc/NetworkManager/system-connections/<conn_id>.nmconnection
    (chmod 0600, owner root:root). After `nmcli connection reload` the
    profile appears in the Network panel and connects in one click.

    private-key-flags=0 means "system-owned" — the secret lives in the
    file itself, NM doesn't ask the user at connect time. That's the
    setting nmcli's default import is missing.
    """
    import re as _re
    import uuid as _uuid
    # netlink iface name : [a-z0-9-_], max 15 chars. Slugify aggressively
    # so any User-Agent-derived label still produces a valid name.
    safe = _re.sub(r"[^a-z0-9_-]+", "-", conn_id.lower()).strip("-")[:13] or "village3b"
    iface = f"wg-{safe}"[:15]
    uuid = str(_uuid.uuid4())
    return (
        "[connection]\n"
        f"id={conn_id}\n"
        f"uuid={uuid}\n"
        "type=wireguard\n"
        f"interface-name={iface}\n"
        "autoconnect=false\n"
        "\n"
        "[wireguard]\n"
        f"private-key={priv}\n"
        "private-key-flags=0\n"
        "listen-port=0\n"
        "fwmark=0\n"
        "\n"
        f"[wireguard-peer.{server_pub}]\n"
        f"endpoint={WG_ENDPOINT}:{WG_PORT}\n"
        "persistent-keepalive=25\n"
        "allowed-ips=0.0.0.0/0;::/0;\n"
        "\n"
        "[ipv4]\n"
        f"address1={client_ip}/32\n"
        "dns=10.99.1.1;\n"
        "method=manual\n"
        "\n"
        "[ipv6]\n"
        "addr-gen-mode=default\n"
        "method=disabled\n"
        "\n"
        "[proxy]\n"
    )


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

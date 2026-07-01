# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-exposure :: mesh_egress
Real Mesh channel for service emancipation (gondwana, appstore-federation #768).

Emancipating a service over the MESH channel does two things:
  1. makes the service reachable from mesh peers over the wg-mesh — a durable
     nft allow for its port from 10.10.0.0/24, inserted BEFORE the terminal
     `drop` on vortex-firewall nodes (a rule after the drop is dead; hub nodes
     with a broad 10/8 accept need nothing);
  2. publishes a signed "emancipated" ServiceOffer into the annuaire directory
     (via annuairectl, as the secubox user), so the service federates into every
     node's mesh-wide catalog.

Revoke reverses both. The pure helpers below are unit-tested; apply/revoke shell
out (exposure runs as root, so nft is direct and annuairectl runs as secubox).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional

MESH_NET = "10.10.0.0/24"
NFT_CONF = "/etc/nftables.conf"
EMANCIPATED_KIND = "emancipated"


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested)
# --------------------------------------------------------------------------- #

def mesh_nft_line(port: int) -> str:
    """The nft input rule that lets mesh peers reach <port> over wg-mesh."""
    return f'iifname "wg-mesh" ip saddr {MESH_NET} tcp dport {int(port)} accept'


def mesh_endpoint(ip: str, port: int) -> str:
    return f"http://{ip}:{int(port)}/"


def offer_argv(service: str, endpoint: str, scopes: dict) -> List[str]:
    """Args to publish an emancipated service (one channel) as a signed offer.

    `scopes` becomes repeated --scope key=value pairs (e.g. {'channel':'mesh',
    'port':8090} or {'channel':'tor','onion':'abc.onion'}). Sorted for
    determinism (testable)."""
    argv = ["annuairectl", "offer", "--name", service,
            "--kind", EMANCIPATED_KIND, "--endpoint", endpoint]
    for k in sorted(scopes):
        argv += ["--scope", f"{k}={scopes[k]}"]
    return argv


def insert_before_drop(conf_text: str, rule: str) -> str:
    """Insert `rule` (indented) before the first terminal `drop` line, once.

    If the rule is already present, returns the text unchanged. If there is no
    standalone terminal `drop` (e.g. a hub `inet filter` with a broad accept and
    only a chain `policy drop`), returns unchanged — nothing to insert before.
    """
    if rule in conf_text:
        return conf_text
    out = []
    done = False
    for line in conf_text.splitlines(keepends=True):
        if not done and re.match(r"^[ \t]*drop[ \t]*$", line):
            indent = line[: len(line) - len(line.lstrip())]
            out.append(f"{indent}{rule}\n")
            done = True
        out.append(line)
    return "".join(out) if done else conf_text


# --------------------------------------------------------------------------- #
# Apply / revoke (shell; exposure runs as root)
# --------------------------------------------------------------------------- #

def _run(cmd: List[str], timeout: int = 20) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return False, "", str(e)


def mesh_ip() -> Optional[str]:
    ok, out, _ = _run(["ip", "-4", "-o", "addr", "show", "wg-mesh"])
    if not ok:
        return None
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def ensure_mesh_port(port: int) -> str:
    """Durably allow <port> from the mesh. Returns 'live-broad' | 'inserted' |
    'present' | 'skip'. On vortex nodes edits /etc/nftables.conf (before the
    terminal drop), validates with `nft -c`, reverts on failure, then reloads.
    """
    rule = mesh_nft_line(port)
    conf = Path(NFT_CONF)
    try:
        text = conf.read_text()
    except OSError:
        return "skip"
    if "table inet secubox_filter" not in text:
        return "live-broad"  # hub inet filter has a broad 10/8 accept already
    if rule in text:
        return "present"
    new = insert_before_drop(text, rule)
    if new == text:
        return "skip"
    tmp = str(conf) + ".sbxtmp"
    Path(tmp).write_text(new)
    ok, _, _ = _run(["nft", "-c", "-f", tmp])
    if not ok:
        Path(tmp).unlink(missing_ok=True)
        return "skip"
    Path(tmp).replace(conf)
    _run(["nft", "-f", NFT_CONF])
    return "inserted"


def remove_mesh_port(port: int) -> bool:
    """Remove the durable mesh allow for <port> from /etc/nftables.conf + live."""
    rule = mesh_nft_line(port)
    conf = Path(NFT_CONF)
    try:
        text = conf.read_text()
    except OSError:
        return False
    lines = [ln for ln in text.splitlines(keepends=True) if ln.strip() != rule]
    if len(lines) != len(text.splitlines(keepends=True)):
        conf.write_text("".join(lines))
        _run(["nft", "-f", NFT_CONF])
    return True


def _publish(service: str, endpoint: str, scopes: dict) -> tuple:
    """Publish one emancipated-channel offer into the directory (as secubox)."""
    return _run(["sudo", "-u", "secubox", *offer_argv(service, endpoint, scopes)])


def apply_mesh(service: str, port: int) -> dict:
    """Mesh emancipation: open the port over wg-mesh + register in the directory."""
    ip = mesh_ip()
    if not ip:
        return {"channel": "mesh", "ok": False, "error": "no wg-mesh interface"}
    nft = ensure_mesh_port(port)
    endpoint = mesh_endpoint(ip, port)
    ok, out, err = _publish(service, endpoint, {"channel": "mesh", "port": int(port)})
    return {
        "channel": "mesh", "ok": ok, "mesh_ip": ip, "endpoint": endpoint, "nft": nft,
        "error": None if ok else (err or out).strip(),
    }


def public_vhost_recipe(domain: str, port: int) -> dict:
    """The operator steps to route <domain> to a local :<port> through the WAF.

    Deliberately NOT auto-applied: the live HAProxy/mitmproxy chain has a
    board-wide blast radius, and real reachability needs an operator DNS record
    + TLS cert. We emit the exact recipe (no waf_bypass — always via
    mitmproxy_inspector) so it can be reviewed/applied deliberately.
    """
    return {
        "dns": f"A record {domain} -> the public ingress IP",
        "cert": f"acme.sh --issue -d {domain} -w /usr/share/secubox/www --keylength ec-256",
        "haproxy": f"haproxyctl vhost add {domain} nginx_vhosts ssl   # backend stays mitmproxy_inspector",
        "mitmproxy_route": {domain: ["127.0.0.1", int(port)]},
        "mitmproxy_files": ["/srv/mitmproxy/haproxy-routes.json",
                            "/srv/mitmproxy-in/haproxy-routes.json"],
        "reload": "systemctl restart mitmproxy",
    }


def apply_public(service: str, port: int, domain: str) -> dict:
    """Public emancipation (#768 phase 4): federate a public-channel offer and
    return the WAF/vhost recipe. Reachability is completed by the operator
    (DNS + cert) — we never blindly reconfigure the live WAF."""
    endpoint = f"https://{domain}/"
    ok, out, err = _publish(service, endpoint, {"channel": "public", "domain": domain, "port": int(port)})
    return {
        "channel": "public", "ok": ok, "endpoint": endpoint, "domain": domain,
        "recipe": public_vhost_recipe(domain, port),
        "note": "offer federated; complete public reach with the recipe (DNS + cert + WAF vhost).",
        "error": None if ok else (err or out).strip(),
    }


def apply_tor(service: str, port: int, onion: str) -> dict:
    """Tor emancipation (#768 phase 3): register the .onion into the directory so
    the anonymous egress endpoint federates into every node's catalog. The onion
    itself is created by secubox-tor (exposure's tor_add) before this call."""
    endpoint = f"http://{onion}/"
    ok, out, err = _publish(service, endpoint, {"channel": "tor", "onion": onion, "port": int(port)})
    return {
        "channel": "tor", "ok": ok, "endpoint": endpoint, "onion": onion,
        "error": None if ok else (err or out).strip(),
    }

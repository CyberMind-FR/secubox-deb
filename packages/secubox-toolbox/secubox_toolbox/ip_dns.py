# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Anti-Track v2 Plan 2b IP/DNS helpers (#633)

Pure functions — no nft and no file writes beyond reading the static CDN
allowlist (it also renders unbound DNS-block config lines as strings). Consumed
by escalate.py (exclusive-IP nft-drop). The CDN/cloud allowlist is the
collateral gate: an IP that belongs to shared infrastructure
(Cloudflare/Fastly/Akamai/Google/AWS/Azure) is NEVER dropped, even when a pure
tracker resolves there.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import Callable, Iterable, List

from secubox_toolbox.privacy import registrable

log = logging.getLogger("secubox.toolbox.ip_dns")

CDN_ALLOWLIST_PATH = "/usr/lib/secubox/toolbox/data/cdn-allowlist.txt"

# A registrable domain safe to embed in an unbound `local-zone: "<d>."` directive.
# Guards against malformed tracker domains (e.g. crafted Set-Cookie Domain= values
# with quotes/spaces) breaking the generated unbound config → DNS outage on restart.
_DNS_SAFE = re.compile(r"^[a-z0-9.-]+$")


def load_cdn_allowlist(path: str = CDN_ALLOWLIST_PATH) -> list:
    """Parse a CIDR-per-line file into ip_network objects. Comments (#) and
    blank/malformed lines are skipped. Missing file → []."""
    nets = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        log.warning("cdn-allowlist: not found/unreadable (%s) — allowlist EMPTY, "
                    "no CDN IPs will be exempted: %s", path, e)
        return nets
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            log.warning("cdn-allowlist: skipping malformed CIDR %r", s)
    return nets


def ip_in_allowlist(ip: str, networks: Iterable) -> bool:
    """True if ip falls inside any allow-network. Malformed ip → False."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False


def exclusive_tracker_ips(pure_hosts: Iterable[str],
                          resolve: Callable[[str], List[str]],
                          allow_nets: Iterable) -> set:
    """Resolve each pure-tracker host and return the set of IPs that are NOT in
    the CDN/cloud allowlist (so safe to nft-drop). `resolve` is injected
    (escalate._resolve_ips in production) to keep this function pure/testable."""
    allow = list(allow_nets)
    drop: set = set()
    for host in pure_hosts:
        if not host:
            continue
        try:
            ips = resolve(host) or []
        except Exception:
            ips = []
        for ip in ips:
            if ip and not ip_in_allowlist(ip, allow):
                drop.add(ip)
    return drop


def unbound_block_lines(pure_hosts: Iterable[str]) -> list:
    """Render an unbound drop-in body that NXDOMAINs each pure-tracker domain.
    Registrable-folded, deduped, sorted. `server:` is always the first line so
    the file is a valid (possibly empty) unbound conf.d drop-in."""
    zones = set()
    for h in pure_hosts:
        d = registrable(h) if h else ""
        if d and _DNS_SAFE.match(d):
            zones.add(d)
    lines = ["server:",
             "    # SecuBox Anti-Track v2 (#633) — generated; do not edit by hand."]
    for d in sorted(zones):
        lines.append('    local-zone: "%s." always_nxdomain' % d)
    return lines

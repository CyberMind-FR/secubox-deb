# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: Anti-Track v2 Plan 2b IP/DNS helpers (#633)

Pure functions — no nft, no DNS, no file writes beyond reading the static CDN
allowlist. Consumed by escalate.py (exclusive-IP nft-drop). The CDN/cloud
allowlist is the collateral gate: an IP that belongs to shared infrastructure
(Cloudflare/Fastly/Akamai/Google/AWS/Azure) is NEVER dropped, even when a pure
tracker resolves there.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Callable, Iterable, List

log = logging.getLogger("secubox.toolbox.ip_dns")

CDN_ALLOWLIST_PATH = "/usr/lib/secubox/toolbox/data/cdn-allowlist.txt"


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

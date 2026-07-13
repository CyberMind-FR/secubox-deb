# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — unified dnsmasq + ISC + ARP discovery merge
(#817 Task 2).

Merges the three legacy passive-discovery sources (nac's own dnsmasq
`_parse_leases`, device-intel's ISC `dhcpd.leases` block parser, and
nac's `_parse_arp` `ip neigh` parser restricted to `LAN_INTERFACES`) into
one canonical device dict per MAC address, keyed by `store.canon_mac`.

Pure stdlib, no FastAPI import. Every source is independently
best-effort: a missing file, unreadable path, or a raising `arp_cmd`
contributes nothing for that source and never raises — `discover()`
degrades to `[]` when all three sources are unavailable, per the
Global Constraints fail-safe requirement.
"""
from __future__ import annotations

import logging
import re
import subprocess

from .store import canon_mac

logger = logging.getLogger("secubox.nac.discovery")

# Default legacy lease/lookup locations (overridable for tests).
DEFAULT_DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"
DEFAULT_ISC_LEASES = "/var/lib/dhcp/dhcpd.leases"

# Interfaces to scan for ARP entries (LAN interfaces only, + the secubox LXC
# bridge br-lxc so containers are discovered and can auto-classify into the
# `lxc` zone — see main.py `_interface_zones`) — lifted
# verbatim from secubox-nac's `api/main.py` `_parse_arp`.
LAN_INTERFACES = {"lan0", "lan1", "lan2", "lan3", "br0", "br-lan", "br-lxc", "eth0", "eth1"}

# Confidence ranking used to decide which source's data wins a merge:
# a lease-backed sighting (dnsmasq, then isc) always beats a bare ARP
# sighting for the same MAC.
_SOURCE_RANK = {"dnsmasq": 3, "isc": 2, "arp": 1}


def _default_arp_cmd() -> str:
    """Default `arp_cmd`: run `ip neigh show` and return its stdout."""
    r = subprocess.run(
        ["ip", "neigh", "show"],
        capture_output=True, text=True, timeout=5,
    )
    if r.returncode != 0:
        return ""
    return r.stdout


def _parse_dnsmasq(path: str) -> list[dict]:
    """Parse a dnsmasq `.leases` file: `<expiry> <mac> <ip> <hostname> <id>`.

    Lifted from secubox-nac's `api/main.py` `_parse_leases`.
    """
    out: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return out

    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        mac = canon_mac(parts[1])
        if not mac:
            continue
        hostname = parts[3] if parts[3] != "*" else ""
        out.append({
            "mac": mac,
            "ip": parts[2],
            "hostname": hostname,
            "source": "dnsmasq",
        })
    return out


_ISC_LEASE_BLOCK_RE = re.compile(r"lease\s+([\d.]+)\s*{([^}]+)}", re.MULTILINE)
_ISC_MAC_RE = re.compile(r"hardware ethernet\s+([0-9a-fA-F:]+)")
_ISC_HOSTNAME_RE = re.compile(r'client-hostname\s+"([^"]+)"')


def _parse_isc(path: str) -> list[dict]:
    """Parse an ISC `dhcpd.leases` file: `lease <ip> { hardware ethernet
    <MAC>; client-hostname "<h>"; }` blocks.

    Lifted from secubox-device-intel's `api/main.py` `_get_dhcp_leases`
    (ISC branch).
    """
    out: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError:
        return out

    for ip, block in _ISC_LEASE_BLOCK_RE.findall(content):
        mac_match = _ISC_MAC_RE.search(block)
        if not mac_match:
            continue
        mac = canon_mac(mac_match.group(1))
        if not mac:
            continue
        hostname_match = _ISC_HOSTNAME_RE.search(block)
        out.append({
            "mac": mac,
            "ip": ip,
            "hostname": hostname_match.group(1) if hostname_match else "",
            "source": "isc",
        })
    return out


def _parse_arp(arp_text: str) -> list[dict]:
    """Parse `ip neigh show` output, restricted to `LAN_INTERFACES`.

    Lifted from secubox-nac's `api/main.py` `_parse_arp`.
    """
    out: list[dict] = []
    for line in arp_text.splitlines():
        # Format: IP dev IFACE lladdr MAC STATE
        parts = line.split()
        if len(parts) < 5:
            continue

        ip = parts[0]
        iface = parts[2] if len(parts) > 2 and parts[1] == "dev" else ""
        mac = ""
        state = ""

        for i, part in enumerate(parts):
            if part == "lladdr" and i + 1 < len(parts):
                mac = parts[i + 1]
            if part in ("REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"):
                state = part

        if not mac or state == "FAILED":
            continue

        if iface and iface not in LAN_INTERFACES:
            continue

        if ip.startswith("fe80:"):
            continue

        canon = canon_mac(mac)
        if not canon:
            continue

        out.append({
            "mac": canon,
            "ip": ip,
            "hostname": "",
            "interface": iface,
            "source": "arp",
        })
    return out


def discover(*, dnsmasq_leases=DEFAULT_DNSMASQ_LEASES, isc_leases=DEFAULT_ISC_LEASES,
             arp_cmd=_default_arp_cmd) -> list[dict]:
    """Merge dnsmasq + ISC + ARP sightings into one dict per canonical MAC.

    Each returned dict is `{mac, ip, hostname, source}`. `source` records
    the highest-confidence origin seen for that MAC (`dnsmasq` > `isc` >
    `arp`); a source that supplies a non-empty hostname wins the
    hostname over one that doesn't (a bare ARP sighting never overwrites
    a lease-backed hostname). Any single source failing (missing file,
    a raising `arp_cmd`) contributes nothing for that source and never
    raises — an all-sources-failing call returns `[]`.
    """
    sightings: list[dict] = []

    try:
        sightings.extend(_parse_dnsmasq(dnsmasq_leases))
    except Exception:  # noqa: BLE001 - a source must never abort discovery
        logger.warning("discover: dnsmasq source failed", exc_info=True)

    try:
        sightings.extend(_parse_isc(isc_leases))
    except Exception:  # noqa: BLE001
        logger.warning("discover: isc source failed", exc_info=True)

    try:
        arp_text = arp_cmd()
        sightings.extend(_parse_arp(arp_text or ""))
    except Exception:  # noqa: BLE001
        logger.warning("discover: arp source failed", exc_info=True)

    merged: dict[str, dict] = {}
    for s in sightings:
        mac = s["mac"]
        existing = merged.get(mac)
        if existing is None:
            merged[mac] = dict(s)
            continue

        # Winning source: prefer higher confidence rank; on a tie, the
        # later sighting wins (latest ISC lease block supersedes an
        # earlier one for the same MAC). Never let a higher-rank
        # sighting with no hostname clobber an already-known hostname
        # from a lower-rank sighting.
        incoming_rank = _SOURCE_RANK.get(s["source"], 0)
        existing_rank = _SOURCE_RANK.get(existing["source"], 0)

        if s.get("hostname"):
            existing["hostname"] = s["hostname"]
        # Interface comes only from the ARP pass (lowest rank), but it must
        # survive even when a higher-rank lease sighting owns the record —
        # otherwise a br-lxc container that also has a DHCP lease loses the
        # interface and never auto-classifies into the `lxc` zone. Same
        # "keep any non-empty value" rule as hostname.
        if s.get("interface"):
            existing["interface"] = s["interface"]
        if incoming_rank >= existing_rank:
            # Equal-rank sightings arrive in fixed dnsmasq -> isc -> arp
            # order, so multiple same-rank sightings for one MAC are
            # successive blocks of the *same* source (e.g. repeated ISC
            # `dhcpd.leases` blocks emitted on every lease renewal). The
            # latest one reflects the current IP and must win, mirroring
            # secubox-device-intel's `_get_dhcp_leases` (`leases[mac] =
            # {...}` — last block wins outright).
            existing["source"] = s["source"]
            if s.get("ip"):
                existing["ip"] = s["ip"]
        elif not existing.get("ip"):
            existing["ip"] = s.get("ip")

    return list(merged.values())

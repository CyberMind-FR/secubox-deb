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
#820 (ref #817 follow-up): `resolve_hostname()` added — on the reference
board nac is NOT the LAN DHCP server, so ARP-only sightings carry no
hostname at all. Reverse-DNS (and, best-effort, mDNS) fills that gap for
the small set of currently-seen devices — never the whole store.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time

from .store import canon_mac

logger = logging.getLogger("secubox.nac.discovery")

# --- Hostname resolution (reverse-DNS + best-effort mDNS), #820 ref #817 ---

# Module-level TTL cache: {ip: (resolved_at_monotonic, hostname_or_None)}.
# A cached `None` still counts as a cache hit — an IP with no PTR record
# must not be re-queried every collector cycle. Tests can clear this dict
# directly (`discovery._HOSTNAME_CACHE.clear()`) to bypass it.
_HOSTNAME_CACHE: dict[str, tuple[float, str | None]] = {}
_HOSTNAME_CACHE_TTL = 300.0  # seconds

# Bounded bare minimum: a hung resolver must not stall the collector
# cycle. 1.0s for reverse-DNS, a bit more slack for the avahi subprocess
# (process spawn overhead on top of the network round-trip).
_DNS_TIMEOUT = 1.0
_MDNS_TIMEOUT = 1.5


def _reverse_dns(ip: str) -> str | None:
    """Bounded reverse-DNS lookup via `getent hosts <ip>` (NSS: files then
    DNS, same chain `socket.gethostbyaddr` would consult).

    Deliberately NOT `socket.gethostbyaddr()` guarded by
    `socket.setdefaulttimeout()`: that guard is a no-op for this call —
    `setdefaulttimeout()` only affects newly-created `socket.socket()`
    objects, not the C library resolver `gethostbyaddr()` invokes
    directly, so a slow/unreachable DNS server would block past
    `_DNS_TIMEOUT` anyway. Running `getent` as a subprocess makes the
    bound real: `subprocess.run(..., timeout=...)` kills the child
    process on expiry, so this call can never hang the caller past
    `_DNS_TIMEOUT` regardless of what the resolver is doing. Never
    raises — any failure (NXDOMAIN, timeout, missing binary, malformed
    input) yields `None`.
    """
    try:
        r = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True, text=True, timeout=_DNS_TIMEOUT,
        )
        if r.returncode != 0:
            return None
        # Expected stdout: "<ip>    <name>[ <alias>...]"
        line = (r.stdout or "").strip().splitlines()[0] if r.stdout else ""
        parts = line.split()
        if len(parts) < 2:
            return None
        return parts[1]
    except Exception:  # noqa: BLE001 - a resolver failure must never raise
        return None


def _mdns_resolve(ip: str) -> str | None:
    """Best-effort mDNS resolve via `avahi-resolve-address`, only if the
    binary is present. Fail-safe: missing binary / non-zero exit / parse
    miss / timeout all yield `None`, never raise.
    """
    if not shutil.which("avahi-resolve-address"):
        return None
    try:
        r = subprocess.run(
            ["avahi-resolve-address", "-4", ip],
            capture_output=True, text=True, timeout=_MDNS_TIMEOUT,
        )
        if r.returncode != 0:
            return None
        # Expected stdout: "<ip>\t<name>.local"
        line = (r.stdout or "").strip().splitlines()[0] if r.stdout else ""
        parts = line.split()
        if len(parts) < 2:
            return None
        return parts[1]
    except Exception:  # noqa: BLE001
        return None


def _short_lower(name: str | None, ip: str) -> str | None:
    """Strip everything after the first `.`, lowercase, and reject an
    empty result or one that just echoes the IP back (some resolvers do
    this instead of failing).

    The IP-echo check MUST run against the untouched `name` before
    splitting on `.` — an IPv4 address contains dots too, so comparing
    the already-split short form against `ip` would never match.
    """
    if not name:
        return None
    name = name.strip()
    if not name or name == ip:
        return None
    short = name.split(".", 1)[0].lower()
    if not short or short == ip:
        return None
    return short


def resolve_hostname(ip: str) -> str | None:
    """Resolve `ip` to a short, lowercased hostname, or `None`.

    Primary: reverse-DNS (`getent hosts`, bounded to `_DNS_TIMEOUT` via a
    subprocess timeout). Secondary, only when reverse-DNS found nothing and
    `avahi-resolve-address` is installed: best-effort mDNS. Results
    (including negative ones) are cached for `_HOSTNAME_CACHE_TTL`
    seconds so a device with no PTR/mDNS record isn't re-queried every
    collector cycle. Never raises — any internal failure degrades to
    `None`, exactly like a genuine resolution miss.
    """
    try:
        now = time.monotonic()
        cached = _HOSTNAME_CACHE.get(ip)
        if cached is not None and (now - cached[0]) < _HOSTNAME_CACHE_TTL:
            return cached[1]

        result = _short_lower(_reverse_dns(ip), ip)
        if not result:
            result = _short_lower(_mdns_resolve(ip), ip)

        _HOSTNAME_CACHE[ip] = (now, result)
        return result
    except Exception:  # noqa: BLE001 - resolution must never raise out
        logger.warning("resolve_hostname: failed for ip=%r", ip, exc_info=True)
        return None

# Default legacy lease/lookup locations (overridable for tests).
DEFAULT_DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"
DEFAULT_ISC_LEASES = "/var/lib/dhcp/dhcpd.leases"

# Interfaces to scan for ARP entries (LAN interfaces only) — lifted
# from secubox-nac's `api/main.py` `_parse_arp`. `eth2` added because on the
# reference board the LAN (192.168.1.0/24) rides eth2 (the previous set omitted
# it, so ARP discovery found nothing and every device stayed a stale import).
LAN_INTERFACES = {"lan0", "lan1", "lan2", "lan3", "br0", "br-lan", "eth0", "eth1", "eth2"}

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

    result = list(merged.values())

    # #820 (ref #817): fill hostnames for devices no lease source named
    # (typical on this board, where nac isn't the DHCP server so ARP-only
    # sightings carry no hostname). Only the small MERGED live set is
    # resolved here, never the whole store, and only an EMPTY hostname is
    # filled — a lease-backed hostname is never overwritten. A resolver
    # failure/timeout contributes nothing for that one device and never
    # aborts the merge.
    for device in result:
        if device.get("hostname"):
            continue
        try:
            name = resolve_hostname(device.get("ip", ""))
        except Exception:  # noqa: BLE001 - resolution must never abort discover()
            logger.warning("discover: resolve_hostname failed for mac=%s", device.get("mac"), exc_info=True)
            name = None
        if name:
            device["hostname"] = name

    return result

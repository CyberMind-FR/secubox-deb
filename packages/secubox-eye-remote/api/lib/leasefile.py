# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: dnsmasq lease file parser.

Each line: <expiry-epoch> <mac> <ip> <hostname-or-*> <client-id>
The file lives at /var/lib/misc/dnsmasq-eye-remote.leases on the host.

Lenient by design: the file is daemon-managed, partial writes are
possible during lease churn, and DHCPv6 lines (with a DUID in the MAC
position and an IPv6 address) would parse-through to Lease objects
that fail to match any IPv4 reservation. We accept that — eye-br0 is
v4-only — and let downstream consumers ignore non-matching records.
Strict MAC validation is intentionally absent here: `reservations.py`
validates at the admin-edited boundary; this module trusts dnsmasq.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lease:
    expiry: int
    mac: str
    ip: str
    hostname: str | None
    client_id: str | None


def parse_leases(src: str) -> list[Lease]:
    out: list[Lease] = []
    for raw in src.splitlines():
        parts = raw.strip().split()
        if len(parts) < 4:
            continue
        try:
            expiry = int(parts[0])
        except ValueError:
            continue
        mac = parts[1]
        ip = parts[2]
        hostname = parts[3] if parts[3] != "*" else None
        client_id = parts[4] if len(parts) >= 5 else None
        out.append(Lease(expiry, mac, ip, hostname, client_id))
    return out

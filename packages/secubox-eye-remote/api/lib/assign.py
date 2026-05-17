# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote IP auto-assignment.

Picks the lowest free /24 octet in [11, 250] given the current
reservation set. .1 is the host bridge gateway and is never assigned;
.2..10 are reserved for static debugging / future use.
"""
from __future__ import annotations

from typing import Iterable

from .reservations import Reservation

POOL_START = 11
POOL_END = 250
SUBNET_PREFIX = "10.55.0."


def assign_ip(reservations: Iterable[Reservation]) -> str:
    taken: set[int] = set()
    for r in reservations:
        if not r.ip.startswith(SUBNET_PREFIX):
            continue
        try:
            taken.add(int(r.ip.removeprefix(SUBNET_PREFIX)))
        except ValueError:
            continue
    for octet in range(POOL_START, POOL_END + 1):
        if octet not in taken:
            return f"{SUBNET_PREFIX}{octet}"
    raise RuntimeError("eye-remote DHCP pool exhausted (.11–.250 all in use)")

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote reservations parser.

Reads / writes dnsmasq `dhcp-host=` lines stored in
/etc/secubox/eye-remote/reservations.conf. The file is conffile-managed,
so we never rewrite it in place — we only append.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_LINE_RE = re.compile(r"^dhcp-host=([^,]+),([^,]+),([^,]*),([^,\n]+)\s*$")


@dataclass(frozen=True)
class Reservation:
    mac: str
    ip: str
    hostname: str
    lease_time: str

    def __post_init__(self) -> None:
        if not _MAC_RE.match(self.mac):
            raise ValueError(f"invalid MAC: {self.mac!r}")


def parse_reservations(src: str) -> list[Reservation]:
    """Parse the textual contents of reservations.conf.

    Comments (`#…`) and blank lines are ignored. Any non-blank, non-comment
    line that does not match the `dhcp-host=` shape raises ValueError so
    we never silently drop user-edited lines.
    """
    out: list[Reservation] = []
    for raw in src.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            raise ValueError(f"unparseable line: {line!r}")
        out.append(Reservation(m.group(1), m.group(2), m.group(3), m.group(4)))
    return out


def serialize_reservation(r: Reservation) -> str:
    return f"dhcp-host={r.mac},{r.ip},{r.hostname},{r.lease_time}"


def append_reservation(path: Path, r: Reservation) -> bool:
    """Append a reservation to `path` if no entry for its MAC exists.

    Returns True if the file was modified, False if the exact MAC was
    already present. Raises ValueError if the MAC is present but bound to
    a different IP / hostname — we never silently overwrite.
    """
    existing: list[Reservation] = []
    if path.exists():
        existing = parse_reservations(path.read_text(encoding="utf-8"))
    for cur in existing:
        if cur.mac.lower() != r.mac.lower():
            continue
        if cur == r:
            return False
        raise ValueError(
            f"conflict: MAC {r.mac} already maps to {cur.ip}/{cur.hostname}"
        )
    needs_separator = (
        path.exists() and path.stat().st_size > 0
        and not path.read_bytes().endswith(b"\n")
    )
    with path.open("a", encoding="utf-8") as fh:
        if needs_separator:
            fh.write("\n")
        fh.write(serialize_reservation(r) + "\n")
    return True


def filter_active(
    reservations: Iterable[Reservation], active_macs: Iterable[str]
) -> list[Reservation]:
    active = {m.lower() for m in active_macs}
    return [r for r in reservations if r.mac.lower() in active]

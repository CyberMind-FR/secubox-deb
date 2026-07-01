# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: threatmesh apply (#768)

Turns the federated ban union (verbs.banned_ips) into a self-contained nft table
`inet secubox_meshban` that DROPs banned sources. It owns its own table (like
secubox-metrics) and NEVER edits the main firewall, so it has no board-wide blast
radius. The applier flushes + rebuilds the set each run, so directory-expired /
revoked bans fall out automatically. IPv4 for now (IPv6 is a follow-up).
"""
from __future__ import annotations

import ipaddress
import subprocess
from typing import List


def is_ipv4(addr: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(addr), ipaddress.IPv4Address)
    except ValueError:
        return False


def meshban_ruleset(ips: List[str]) -> str:
    """Render the self-contained nft table dropping the given (IPv4) sources."""
    v4 = sorted({i for i in ips if is_ipv4(i)})
    elems = f"\n        elements = {{ {', '.join(v4)} }}" if v4 else ""
    return (
        "table inet secubox_meshban {\n"
        "    set banned {\n"
        "        type ipv4_addr" + elems + "\n"
        "    }\n"
        "    chain input {\n"
        "        type filter hook input priority -5; policy accept;\n"
        "        ip saddr @banned drop\n"
        "    }\n"
        "}\n"
    )


def apply_bans(ips: List[str]) -> dict:
    """(Re)build the secubox_meshban table from the union. Validated, atomic."""
    ruleset = meshban_ruleset(ips)
    v4 = [i for i in ips if is_ipv4(i)]
    try:
        chk = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset,
                             text=True, capture_output=True, timeout=15)
        if chk.returncode != 0:
            return {"ok": False, "count": len(v4), "error": chk.stderr.strip()}
        subprocess.run(["nft", "delete", "table", "inet", "secubox_meshban"],
                       capture_output=True, timeout=10)  # ignore if absent
        r = subprocess.run(["nft", "-f", "-"], input=ruleset,
                          text=True, capture_output=True, timeout=15)
        return {"ok": r.returncode == 0, "count": len(v4),
                "error": None if r.returncode == 0 else r.stderr.strip()}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "count": len(v4), "error": str(e)}

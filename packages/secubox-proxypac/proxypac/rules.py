# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.rules — rule model, rules.d parsing, precedence."""
from dataclasses import dataclass
from pathlib import Path

from .pac_template import directive


@dataclass
class Rule:
    host: str
    directive: str  # full PAC directive string
    source: str     # "override" | "service:<id>" | "toolbox"


def parse_rules_dir(path):
    """Parse rules.d/*.rules in sorted filename order.

    Line: '<host-glob> <proxy_type> [address]'. '#' comments and blanks skipped.
    """
    path = Path(path)
    rules = []
    for f in sorted(path.glob("*.rules")):
        for raw in f.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            host, ptype = parts[0], parts[1]
            addr = parts[2] if len(parts) > 2 else ""
            rules.append(Rule(host, directive(ptype, addr), "override"))
    return rules


def compose(overrides, services, toolbox):
    """Compose the final ordered (host, directive) rule list.

    Cross-source precedence: overrides beat services beat the toolbox catch-all
    (they are emitted in that order, and PAC matches first-listed host first).

    Within the overrides, the LAST definition of a host wins, so an operator's
    later file (e.g. 50-webui.rules written by the WebUI) overrides a shipped seed
    (e.g. 00-onion.rules) for the same host glob — explicit policy beats defaults.
    Each host keeps the position of its first appearance so glob ordering is stable.
    """
    # Overrides: last definition per host wins (dict keeps last value, first-seen order).
    ov = {}
    for r in overrides:
        ov[r.host] = r
    seen = set()
    out = []
    ordered = list(ov.values()) + list(services) + ([toolbox] if toolbox else [])
    for r in ordered:
        if r.host in seen:
            continue
        seen.add(r.host)
        out.append((r.host, r.directive))
    return out

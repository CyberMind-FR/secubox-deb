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
    """Precedence: overrides, then services, then toolbox catch-all. First host wins."""
    seen = set()
    out = []
    ordered = list(overrides) + list(services) + ([toolbox] if toolbox else [])
    for r in ordered:
        if r.host in seen:
            continue
        seen.add(r.host)
        out.append((r.host, r.directive))
    return out

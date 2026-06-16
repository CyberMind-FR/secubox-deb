# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — domain model
CyberMind — https://cybermind.fr

Pure data structures shared by the collectors, the scoring engine and the API
layer. No I/O here. The cardinal rule of this module: an Indicator only carries
a numeric ``value`` when it was *actually measured*. When a source is
unreachable (UNKNOWN) or a check is human-judged (MANUAL), ``value`` is ``None``
and the indicator is excluded from the score denominator by scoring.py.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class Status(str, enum.Enum):
    """Indicator / domain health.

    OK / WARN / CRIT carry a numeric value and count toward the score.
    UNKNOWN (source unreachable) and MANUAL (human-judged) do not.
    """

    OK = "ok"
    WARN = "warn"
    CRIT = "crit"
    UNKNOWN = "unknown"
    MANUAL = "manual"

    @property
    def is_scored(self) -> bool:
        """True when this status contributes to a numeric score."""
        return self in (Status.OK, Status.WARN, Status.CRIT)


# The six SecuBox module-domains (Design Charter §Six Module Color System).
DOMAINS = ("auth", "wall", "boot", "mind", "root", "mesh")

DOMAIN_META = {
    "auth": {"name": "Auth", "color": "#C04E24", "icon": "🎯",
             "blurb": "Authentication & zero-trust", "link": "/auth/"},
    "wall": {"name": "Wall", "color": "#9A6010", "icon": "🛡️",
             "blurb": "Firewall, WAF & IDS", "link": "/waf/"},
    "boot": {"name": "Boot", "color": "#803018", "icon": "🚀",
             "blurb": "Hardening, backup & integrity", "link": "/hardening/"},
    "mind": {"name": "Mind", "color": "#3D35A0", "icon": "🤖",
             "blurb": "DPI & behavioural analysis", "link": "/dpi/"},
    "root": {"name": "Root", "color": "#0A5840", "icon": "⚙️",
             "blurb": "System & Debian health", "link": "/system/"},
    "mesh": {"name": "Mesh", "color": "#104A88", "icon": "🌐",
             "blurb": "Network, VPN, certs & DNS", "link": "/wireguard/"},
}


@dataclass
class Provenance:
    """Where an indicator's value came from — the honesty contract."""

    source: str               # e.g. "socket:waf.sock /stats" or "/proc/loadavg"
    ok: bool = True           # False when the source failed → UNKNOWN
    note: str = ""            # short human note (error text, "human-judged", …)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Indicator:
    """A single measured (or explicitly unmeasured) security signal.

    ``value`` is normalised to 0.0–1.0 (1.0 = best). It is ``None`` for
    UNKNOWN/MANUAL indicators, which are excluded from scoring.
    """

    id: str
    domain: str
    label: str
    status: Status
    provenance: Provenance
    value: Optional[float] = None
    weight: float = 1.0
    detail: str = ""
    remediation: Optional[str] = None
    link: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class DomainScore:
    """Aggregated score for one module-domain."""

    domain: str
    score: Optional[float]            # 0–100, None when coverage == 0
    coverage: float                   # 0.0–1.0 = scored / total indicators
    status: Status
    indicators: list = field(default_factory=list)

    def to_dict(self) -> dict:
        meta = DOMAIN_META.get(self.domain, {})
        return {
            "domain": self.domain,
            "name": meta.get("name", self.domain.title()),
            "color": meta.get("color"),
            "icon": meta.get("icon"),
            "blurb": meta.get("blurb"),
            "link": meta.get("link"),
            "score": self.score,
            "coverage": round(self.coverage, 3),
            "status": self.status.value,
            "indicators": [i.to_dict() for i in self.indicators],
        }


@dataclass
class Finding:
    """An actionable remediation item derived from a WARN/CRIT indicator."""

    severity: str                     # "crit" | "warn"
    domain: str
    title: str
    detail: str = ""
    remediation: Optional[str] = None
    link: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

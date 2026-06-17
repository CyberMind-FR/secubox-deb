# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — scoring engine (pure)
CyberMind — https://cybermind.fr

No I/O. Turns a flat list of measured Indicators into per-domain scores, an
overall score, a DEFCON level, and a sorted findings list. Unit-tested in
tests/test_scoring.py — keep it pure so it stays testable.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .model import (
    DOMAINS,
    DomainScore,
    Finding,
    Indicator,
    Status,
)

# Domain weights for the overall score (sum need not be 1; we normalise over the
# domains that actually have a score). WALL leads — firewall/WAF/IDS is the
# appliance's primary job; AUTH/ROOT next; then MESH, MIND, BOOT.
DOMAIN_WEIGHTS = {
    "wall": 0.22,
    "auth": 0.18,
    "root": 0.18,
    "mesh": 0.16,
    "mind": 0.14,
    "boot": 0.12,
}

# DEFCON bands: (min_score_inclusive, level, name, color, emoji, blink).
# Colours come straight from the Design Charter module palette.
_DEFCON_BANDS = [
    (90, 5, "Normal",   "#0A5840", "🟢", False),  # root green
    (75, 4, "Elevated", "#104A88", "🔵", False),  # mesh blue
    (55, 3, "Guarded",  "#9A6010", "🟡", False),  # wall amber
    (35, 2, "High",     "#C06040", "🟠", True),   # boot light
    (0,  1, "Critical", "#803018", "🔴", True),   # boot red
]


def status_of(value: float, ok: float = 0.8, warn: float = 0.5) -> Status:
    """Map a 0..1 indicator value to a status. value >= ok → OK, >= warn → WARN."""
    if value >= ok:
        return Status.OK
    if value >= warn:
        return Status.WARN
    return Status.CRIT


def domain_score(indicators: List[Indicator]) -> Tuple[Optional[float], float]:
    """Weighted mean (0–100) over *scored* indicators, plus coverage ratio.

    UNKNOWN / MANUAL indicators are excluded from the weighted mean but counted
    in the coverage denominator. Returns ``(None, 0.0)`` when nothing was
    measured.
    """
    total = len(indicators)
    if total == 0:
        return None, 0.0

    scored = [i for i in indicators if i.status.is_scored and i.value is not None]
    coverage = len(scored) / total
    if not scored:
        return None, 0.0

    wsum = sum(i.weight for i in scored) or 1.0
    mean = sum((i.value or 0.0) * i.weight for i in scored) / wsum
    return round(mean * 100, 1), coverage


def domain_status(score: Optional[float]) -> Status:
    """Status for a whole domain from its 0–100 score."""
    if score is None:
        return Status.UNKNOWN
    return status_of(score / 100.0)


def build_domain_scores(indicators: List[Indicator]) -> List[DomainScore]:
    """Group indicators by domain (charter order) and score each group."""
    out: List[DomainScore] = []
    for dom in DOMAINS:
        group = [i for i in indicators if i.domain == dom]
        score, coverage = domain_score(group)
        out.append(DomainScore(
            domain=dom,
            score=score,
            coverage=coverage,
            status=domain_status(score),
            indicators=group,
        ))
    return out


def overall_score(domain_scores: List[DomainScore]) -> Optional[float]:
    """Weighted mean over domains that have a score; ``None`` if none do."""
    scored = [d for d in domain_scores if d.score is not None]
    if not scored:
        return None
    wsum = sum(DOMAIN_WEIGHTS.get(d.domain, 0.1) for d in scored) or 1.0
    acc = sum(d.score * DOMAIN_WEIGHTS.get(d.domain, 0.1) for d in scored)
    return round(acc / wsum, 1)


def defcon(score: Optional[float]) -> dict:
    """Map an overall score to a DEFCON payload (level/name/color/emoji/blink)."""
    if score is None:
        return {"level": None, "name": "Unknown", "color": "#8A9AA8",
                "emoji": "⚫", "blink": False, "score": None}
    for threshold, level, name, color, emoji, blink in _DEFCON_BANDS:
        if score >= threshold:
            return {"level": level, "name": name, "color": color,
                    "emoji": emoji, "blink": blink, "score": score}
    # Unreachable (last band starts at 0) but keep the type stable.
    return {"level": 1, "name": "Critical", "color": "#803018",
            "emoji": "🔴", "blink": True, "score": score}


def findings_from(domain_scores: List[DomainScore]) -> List[Finding]:
    """Derive actionable findings from WARN/CRIT indicators, CRIT first."""
    findings: List[Finding] = []
    for ds in domain_scores:
        for ind in ds.indicators:
            if ind.status in (Status.WARN, Status.CRIT):
                findings.append(Finding(
                    severity="crit" if ind.status is Status.CRIT else "warn",
                    domain=ind.domain,
                    title=ind.label,
                    detail=ind.detail,
                    remediation=ind.remediation,
                    link=ind.link,
                ))
    findings.sort(key=lambda f: 0 if f.severity == "crit" else 1)
    return findings

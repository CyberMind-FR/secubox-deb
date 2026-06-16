# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — scoring tests (TDD)
CyberMind — https://cybermind.fr
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from posture.model import Indicator, Provenance, Status  # noqa: E402
from posture import scoring  # noqa: E402


def _ind(value, status, weight=1.0, domain="wall"):
    return Indicator(
        id="x", domain=domain, label="x", status=status,
        provenance=Provenance("test"), value=value, weight=weight,
    )


# ---- status_of -------------------------------------------------------------

def test_status_of_thresholds():
    assert scoring.status_of(0.95) is Status.OK
    assert scoring.status_of(0.80) is Status.OK
    assert scoring.status_of(0.79) is Status.WARN
    assert scoring.status_of(0.50) is Status.WARN
    assert scoring.status_of(0.49) is Status.CRIT
    assert scoring.status_of(0.0) is Status.CRIT


def test_status_of_custom_thresholds():
    assert scoring.status_of(0.6, ok=0.9, warn=0.6) is Status.WARN
    assert scoring.status_of(0.59, ok=0.9, warn=0.6) is Status.CRIT


# ---- domain_score ----------------------------------------------------------

def test_domain_score_weighted_mean():
    inds = [_ind(1.0, Status.OK, weight=1.0), _ind(0.0, Status.CRIT, weight=1.0)]
    score, coverage = scoring.domain_score(inds)
    assert score == 50.0
    assert coverage == 1.0


def test_domain_score_respects_weights():
    inds = [_ind(1.0, Status.OK, weight=3.0), _ind(0.0, Status.CRIT, weight=1.0)]
    score, coverage = scoring.domain_score(inds)
    assert score == 75.0  # (1*3 + 0*1)/4 * 100


def test_domain_score_excludes_unknown_and_manual():
    inds = [
        _ind(1.0, Status.OK, weight=1.0),
        _ind(None, Status.UNKNOWN, weight=5.0),
        _ind(None, Status.MANUAL, weight=5.0),
    ]
    score, coverage = scoring.domain_score(inds)
    assert score == 100.0          # only the OK indicator counts
    assert coverage == 1.0 / 3.0   # 1 of 3 measured


def test_domain_score_none_when_no_coverage():
    inds = [_ind(None, Status.UNKNOWN), _ind(None, Status.MANUAL)]
    score, coverage = scoring.domain_score(inds)
    assert score is None
    assert coverage == 0.0


def test_domain_score_empty():
    score, coverage = scoring.domain_score([])
    assert score is None
    assert coverage == 0.0


# ---- overall_score ---------------------------------------------------------

def test_overall_score_weighted_by_domain():
    from posture.model import DomainScore
    ds = [
        DomainScore("wall", 100.0, 1.0, Status.OK),
        DomainScore("auth", 0.0, 1.0, Status.CRIT),
    ]
    # weights: wall .22, auth .18 → (100*.22 + 0*.18)/(.22+.18) = 55.0
    assert scoring.overall_score(ds) == 55.0


def test_overall_score_skips_unscored_domains():
    from posture.model import DomainScore
    ds = [
        DomainScore("wall", 80.0, 1.0, Status.OK),
        DomainScore("auth", None, 0.0, Status.UNKNOWN),
    ]
    assert scoring.overall_score(ds) == 80.0


def test_overall_score_none_when_all_unscored():
    from posture.model import DomainScore
    ds = [DomainScore("wall", None, 0.0, Status.UNKNOWN)]
    assert scoring.overall_score(ds) is None


# ---- defcon ----------------------------------------------------------------

def test_defcon_levels():
    assert scoring.defcon(95)["level"] == 5
    assert scoring.defcon(90)["level"] == 5
    assert scoring.defcon(89)["level"] == 4
    assert scoring.defcon(75)["level"] == 4
    assert scoring.defcon(74)["level"] == 3
    assert scoring.defcon(55)["level"] == 3
    assert scoring.defcon(54)["level"] == 2
    assert scoring.defcon(35)["level"] == 2
    assert scoring.defcon(34)["level"] == 1
    assert scoring.defcon(0)["level"] == 1


def test_defcon_critical_blinks():
    assert scoring.defcon(10)["blink"] is True
    assert scoring.defcon(95)["blink"] is False


def test_defcon_unknown_when_none():
    d = scoring.defcon(None)
    assert d["level"] is None
    assert d["name"].lower() in ("unknown", "n/a")


def test_defcon_has_color_and_emoji():
    d = scoring.defcon(95)
    assert d["color"].startswith("#")
    assert d["emoji"]

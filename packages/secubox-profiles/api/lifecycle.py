# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — politique de cycle de vie (pure, sans effet de bord)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

from .manifest import Manifest


def effective_lifecycle(m: Manifest) -> str:
    """Un module protégé est TOUJOURS always-on, quoi que déclare le manifeste
    (on ne laisse jamais endormir le cœur — même règle que manifest.protected)."""
    return "always-on" if m.protected else m.lifecycle


def is_sleepable(m: Manifest) -> bool:
    """Seuls eager et on-demand participent au sleep/wake."""
    return effective_lifecycle(m) in ("eager", "on-demand")


def idle_threshold(m: Manifest, *, base: float = 900.0, urgent_mult: float = 4.0) -> float:
    """Durée d'inactivité avant sommeil. urgent dort plus difficilement."""
    return base * urgent_mult if m.wake_class == "urgent" else base


def wake_budget(m: Manifest, *, history_median: float | None = None,
                normal: float = 45.0, urgent: float = 15.0) -> float:
    """Budget de réveil affiché (secondes) : médiane historique si connue, sinon
    défaut par classe."""
    if history_median is not None:
        return history_median
    return urgent if m.wake_class == "urgent" else normal

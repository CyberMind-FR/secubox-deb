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


def boot_should_start(m: Manifest) -> bool:
    """Politique de démarrage au boot (ref #896).

    always-on et eager démarrent immédiatement — le noyau protégé et les
    modules « toujours chauds » ne doivent jamais dépendre d'un premier
    accès pour être disponibles. on-demand et manual restent éteints tant
    qu'une requête réelle (ou un opérateur, pour manual) ne les réveille
    pas : les redémarrer par défaut annulerait tout l'intérêt du
    scale-to-zero dès le premier reboot. `effective_lifecycle` fait déjà
    gagner `protected` sur toute déclaration de manifeste (même règle que
    is_sleepable) : un module protégé est toujours démarré au boot, quoi
    que dise son `lifecycle` déclaré."""
    return effective_lifecycle(m) in ("always-on", "eager")


def watchdog_should_manage(m: Manifest) -> bool:
    """secubox-watchdog ne doit JAMAIS forcer la remise en route d'un module
    sleepable (eager/on-demand, ref #896) — c'est le même invariant que
    l'exclusion des « streamlit sleepers » déjà en place aujourd'hui : dans
    les deux cas, le mécanisme réel de non-relance n'est pas une liste
    séparée mais l'ABSENCE de `lxc.start.auto=1` pendant le sommeil.
    `api/actuate.py::runtime_stop` remet explicitement `lxc.start.auto=0`
    AVANT `lxc-stop` pour cette raison précise (course avec le watchdog
    observée sur la board — voir son commentaire). Cette fonction n'est
    donc pas un générateur de fichier d'exclusion : c'est la politique pure
    qui documente/teste l'invariant — un module sleepable n'est jamais géré
    par le watchdog pendant qu'il dort, un module always-on/manual/protégé
    l'est toujours."""
    return not is_sleepable(m)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — diff état désiré vs état réel
CyberMind — https://cybermind.fr

Fonction pure : produit un plan ORDONNÉ de changements. Phase 1 se contente de
l'afficher ; Phase 3 l'exécutera. L'ordre est une décision de sûreté, pas une
préférence esthétique :

  * tous les stop avant tous les start — la box tourne sur ~2 Go libres, allumer
    avant d'éteindre ferait un pic fatal ;
  * stop par priorité croissante  — le moins prioritaire s'éteint en premier ;
  * start par priorité décroissante — le plus prioritaire s'allume en premier.
"""
from __future__ import annotations

from dataclasses import dataclass

from .manifest import Manifest
from .observe import Actual, is_on
from .state import OFF, ON, Profile, resolve

START, STOP = "start", "stop"


class ProtectedViolation(Exception):
    """Un changement tenterait d'éteindre un module protégé."""


@dataclass(frozen=True)
class Change:
    id: str
    action: str
    reason: str
    priority: int


def plan_changes(manifests: dict[str, Manifest], profile: Profile | None,
                 pins: dict[str, str], actuals: dict[str, Actual]) -> list[Change]:
    """Plan ordonné pour converger vers l'état désiré.

    Lève ProtectedViolation si un pin tente d'éteindre un module protégé — un
    refus, pas un avertissement : un profil qui éteint l'auth laisse
    l'utilisateur sans aucun moyen de revenir.
    """
    for mid, m in manifests.items():
        if m.protected and pins.get(mid) == OFF:
            raise ProtectedViolation(
                f"{mid} est protégé et ne peut pas être épinglé sur 'off'")

    stops: list[Change] = []
    starts: list[Change] = []
    for mid, m in sorted(manifests.items()):
        actual = actuals.get(mid)
        if actual is None:
            continue  # module non observé : pas de changement fantôme
        desired = resolve(m, profile, pins)
        currently_on = is_on(actual)
        if desired == ON and not currently_on:
            starts.append(Change(id=mid, action=START, priority=m.priority,
                                 reason=_reason(m, profile, pins, ON)))
        elif desired == OFF and currently_on:
            stops.append(Change(id=mid, action=STOP, priority=m.priority,
                                reason=_reason(m, profile, pins, OFF)))

    stops.sort(key=lambda c: (c.priority, c.id))            # moins prioritaire d'abord
    starts.sort(key=lambda c: (-c.priority, c.id))          # plus prioritaire d'abord
    return stops + starts


def changements_epingles(changes: list[Change], pins: dict[str, str],
                         sens: str = OFF) -> list[Change]:
    """Ne retient que les changements DUS A UNE EPINGLE, dans un sens donné.

    POURQUOI FILTRER PLUTOT QUE REPLANIFIER (#1028). Un second planificateur
    « spécial épingles » finirait par diverger de celui-ci — sur la protection
    des modules, sur l'ordre, sur un cas limite. On planifie donc une seule
    fois, et l'on choisit ensuite ce qu'on exécute.

    LE SENS COMPTE. Appliquer les épingles `off` n'éteint que ce que
    l'opérateur a explicitement éteint : c'est une opération sûre, qu'une
    minuterie peut répéter sans surprise. ALLUMER, en revanche, démarre des
    services sur une board dont on ne sait rien de la charge — cela reste une
    décision prise à la main, jamais par une minuterie.
    """
    return [c for c in changes if pins.get(c.id) == sens]


def epingles_encore_activees(manifests: dict[str, Manifest], pins: dict[str, str],
                             actuals: dict[str, Actual]) -> list[Change]:
    """Modules épinglés 'off', ARRETES, mais qui redémarreront au prochain boot.

    POURQUOI CE CAS ECHAPPAIT AU PLAN. `is_on` vaut `enabled ET active` : un
    module arrêté à la main mais resté `enabled` est donc vu comme déjà éteint,
    et rien n'est planifié pour lui. Il revient pourtant au démarrage suivant.

    Constaté sur gk2 : huit des neuf modules épinglés `off`, arrêtés, étaient
    encore `enabled`. La décision de l'opérateur ne tenait que jusqu'au
    prochain redémarrage — et personne n'aurait fait le lien.

    « ENCORE ACTIVEE » N'EST PAS « ENCORE ALLUMEE ». On ne touche pas à `is_on`,
    dont la question est « ce module sert-il ? » : la réponse y est juste. La
    question posée ICI est différente — « la décision d'éteindre tiendra-t-elle
    au reboot ? » — et mérite sa propre fonction plutôt qu'un élargissement de
    la première, qui se propagerait au statut, au coût et au diff.
    """
    out: list[Change] = []
    for mid, m in manifests.items():
        if m.protected or pins.get(mid) != OFF:
            continue
        a = actuals.get(mid)
        if a is None or not a.enabled or a.active:
            continue  # déjà désactivé, ou encore allumé (le plan s'en charge)
        out.append(Change(id=mid, action=STOP,
                          reason="épinglé sur 'off' mais encore activé au démarrage",
                          priority=0))
    return out


def _reason(m: Manifest, profile: Profile | None, pins: dict[str, str], desired: str) -> str:
    if m.protected:
        return "module protégé (toujours allumé)"
    if pins.get(m.id) in (ON, OFF):
        return f"épinglé sur '{pins[m.id]}'"
    if profile is not None and m.id in profile.on:
        return f"listé dans le profil '{profile.name}'"
    if profile is not None:
        return f"absent du profil '{profile.name}'"
    return "aucun profil actif"

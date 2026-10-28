# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — état désiré (profils + pins)
CyberMind — https://cybermind.fr

Les profils sont EXHAUSTIFS : ce qui n'est pas listé est éteint, donc basculer
donne le même résultat quel que soit l'état de départ. Les pins réconcilient ce
déterminisme avec le toggle individuel : ils survivent aux bascules.

`resolve` est une fonction pure — c'est la règle la plus critique du système et
elle doit être testable sans board.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .manifest import PROTEGES_COUPABLES, Manifest

ON, OFF = "on", "off"

# Id d'une minuterie : nom de l'unité sans « secubox- » ni « .timer » (« netstats », « cache-warm@jitsi »).
MINUTEUR_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}(?:@[a-z0-9][a-z0-9_.-]{0,62})?")


class StateError(Exception):
    """Profil ou pins illisible/invalide."""


@dataclass(frozen=True)
class Profile:
    name: str
    label: str
    on: frozenset[str]
    # #2897 : entrées de menu masquées tant que le profil est actif (lues aussi par le hub).
    menu_off: frozenset[str] = frozenset()
    # #3218 : minuteries que le profil arrête et désactive ; les autres profils les rétablissent (voir api/minuteurs.py).
    minuteurs_off: frozenset[str] = frozenset()
    # #3218 : modules protégés que CE profil coupe quand même — seulement ceux de PROTEGES_COUPABLES (une voie de secours existe).
    proteges_off: frozenset[str] = frozenset()


def _liste(d: dict, cle: str, path: Path) -> list[str]:
    v = d.get(cle, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise StateError(f"{path}: '{cle}' doit être une liste de chaînes")
    return v


def load_profile(path: Path) -> Profile:
    path = Path(path)
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise StateError(f"{path}: profil illisible: {exc}") from exc
    name = d.get("name")
    if name != path.stem:
        raise StateError(f"{path}: name={name!r} ne correspond pas au fichier {path.stem!r}")
    on = d.get("on", [])
    if not isinstance(on, list) or not all(isinstance(x, str) for x in on):
        raise StateError(f"{path}: 'on' doit être une liste d'ids")
    minuteurs = _liste(d, "minuteurs_off", path)
    for t in minuteurs:
        if not MINUTEUR_ID.fullmatch(t):
            raise StateError(f"{path}: minuterie {t!r} invalide (attendu : nom d'unité sans 'secubox-' ni '.timer')")
    proteges = _liste(d, "proteges_off", path)
    # Refus et non avertissement : un profil qui couperait auth ou l'agrégateur laisserait la box sans moyen d'y revenir.
    interdits = sorted(set(proteges) - PROTEGES_COUPABLES)
    if interdits:
        raise StateError(f"{path}: 'proteges_off' ne peut couper que {sorted(PROTEGES_COUPABLES)} (refusé : {interdits})")
    return Profile(name=name, label=d.get("label", name), on=frozenset(on),
                   menu_off=frozenset(_liste(d, "menu_off", path)), minuteurs_off=frozenset(minuteurs),
                   proteges_off=frozenset(proteges))


def load_pins(path: Path) -> dict[str, str]:
    """Pins absents = cas normal (aucune surcharge), pas une erreur."""
    path = Path(path)
    if not path.exists():
        return {}
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise StateError(f"{path}: pins illisibles: {exc}") from exc
    for k, v in d.items():
        if v not in (ON, OFF):
            raise StateError(f"{path}: pin {k}={v!r} invalide (attendu 'on' ou 'off')")
    return dict(d)


def resolve(m: Manifest, profile: Profile | None, pins: dict[str, str]) -> str:
    """État désiré d'un module. Ordre strict, sans exception :

        protected → ON toujours   (sinon on peut se verrouiller hors de la box)
        épinglé   → valeur du pin
        listé     → ON
        sinon     → OFF
    """
    if m.protected:
        return ON
    pin = pins.get(m.id)
    if pin in (ON, OFF):
        return pin
    if profile is not None and m.id in profile.on:
        return ON
    return OFF

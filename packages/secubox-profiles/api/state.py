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

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest

ON, OFF = "on", "off"


class StateError(Exception):
    """Profil ou pins illisible/invalide."""


@dataclass(frozen=True)
class Profile:
    name: str
    label: str
    on: frozenset[str]


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
    return Profile(name=name, label=d.get("label", name), on=frozenset(on))


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

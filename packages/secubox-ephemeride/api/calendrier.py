# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: calendrier — date, semaine ISO, jour de l'année, saison (fonctions standard, pas de locale)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

JOURS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre",
        "décembre"]

#: Début des saisons astronomiques à ±1 jour près (équinoxes et solstices), dans l'ordre de l'année, hémisphère nord.
SAISONS_NORD = [((3, 20), "printemps"), ((6, 21), "été"), ((9, 22), "automne"), ((12, 21), "hiver")]
OPPOSE = {"printemps": "automne", "été": "hiver", "automne": "printemps", "hiver": "été"}


@dataclass
class Calendrier:
    jour_semaine: str
    jour: int
    mois: str
    annee: int
    semaine_iso: int
    jour_annee: int
    saison: str
    saison_debut: date
    saison_suivante: str
    jours_avant_saison_suivante: int


def _limites(annee: int, sud: bool) -> list[tuple[date, str]]:
    return [(date(annee, m, j), OPPOSE[nom] if sud else nom) for (m, j), nom in SAISONS_NORD]


def infos(m: datetime, latitude: float = 45.0) -> Calendrier:
    """Calendrier du jour LOCAL de `m` (le fuseau de `m` décide de la date)."""
    jour = m.date()
    sud = latitude < 0
    bornes = _limites(jour.year - 1, sud) + _limites(jour.year, sud) + _limites(jour.year + 1, sud)
    courant = max((b for b in bornes if b[0] <= jour), key=lambda b: b[0])
    suivant = min((b for b in bornes if b[0] > jour), key=lambda b: b[0])
    return Calendrier(
        jour_semaine=JOURS[jour.weekday()], jour=jour.day, mois=MOIS[jour.month - 1], annee=jour.year,
        semaine_iso=jour.isocalendar()[1], jour_annee=jour.timetuple().tm_yday,
        saison=courant[1], saison_debut=courant[0], saison_suivante=suivant[1],
        jours_avant_saison_suivante=(suivant[0] - jour).days)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: modèles de données (Pydantic) — EphemerideData et ses parties."""
from __future__ import annotations

from datetime import date, datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .observations import TEXTE_MAX


class Fuseau(BaseModel):
    nom: str
    decalage: str                 # « UTC+2 », « UTC+5:30 », « UTC »
    decalage_minutes: int


class Lieu(BaseModel):
    nom: str
    latitude: float
    longitude: float
    approximatif: bool            # vrai : repli sur la ville du fuseau, pas de coordonnées configurées


class CalendrierModele(BaseModel):
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


class SoleilModele(BaseModel):
    lever: Optional[datetime] = None
    coucher: Optional[datetime] = None
    duree_s: int
    progression: float
    etat: str                     # avant_lever | jour | apres_coucher | jour_polaire | nuit_polaire


class PhaseModele(BaseModel):
    nom: str
    quand: datetime


class LuneModele(BaseModel):
    nom: str
    illumination: float
    age_jours: float
    croissante: bool
    lever: Optional[datetime] = None
    coucher: Optional[datetime] = None
    elongation: float
    prochaine_phase: PhaseModele


class SaintModele(BaseModel):
    nom: str
    description: str = ""
    citation: Optional[str] = None
    image: Optional[str] = None


class MeteoModele(BaseModel):
    temperature_c: float
    condition: str
    icone: str
    code: int
    humidite: Optional[int] = None
    vent_kmh: Optional[float] = None
    observe_a: Optional[str] = None


class AirModele(BaseModel):
    indice: int
    niveau: str
    polluant_principal: Optional[str] = None
    observe_a: Optional[str] = None


class EtatDonnee(BaseModel):
    etat: str                     # frais | perime | indisponible | desactive
    maj: Optional[float] = None   # instant (epoch, secondes) de la dernière mesure réussie


class ObservationModele(BaseModel):
    id: int
    texte: str
    cree: str
    modifie: str


class ObservationEntree(BaseModel):
    texte: str = Field(min_length=1, max_length=TEXTE_MAX)


class Reglages(BaseModel):
    format_24h: bool
    observations: bool


class EphemerideData(BaseModel):
    maintenant: datetime
    serveur_epoch_ms: int
    fuseau: Fuseau
    lieu: Lieu
    calendrier: CalendrierModele
    soleil: SoleilModele
    lune: LuneModele
    saints: List[SaintModele]
    meteo: Optional[MeteoModele] = None
    meteo_etat: EtatDonnee
    air: Optional[AirModele] = None
    air_etat: EtatDonnee
    observations: List[ObservationModele]
    reglages: Reglages

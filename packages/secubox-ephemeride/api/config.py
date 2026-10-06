# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: configuration (TOML) et localisation.

Ordre de préférence du lieu : coordonnées explicites du fichier ; à défaut, la ville de référence du FUSEAU configuré
(marquée « approximatif ») ; à défaut, Paris. Aucune géolocalisation précise n'est jamais exigée, et rien n'est demandé au navigateur.
"""
from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

log = logging.getLogger("ephemeride")

CONF = Path(os.environ.get("SECUBOX_EPH_CONF", "/etc/secubox/ephemeride.toml"))
CONF_DEFAUT = Path(os.environ.get("SECUBOX_EPH_CONF_DEFAUT", "/usr/share/secubox/ephemeride/ephemeride.toml"))

#: Ville de référence par fuseau, pour un repli sans coordonnées (nom, latitude, longitude).
VILLES = {
    "Europe/Paris": ("Paris", 48.8566, 2.3522), "Europe/London": ("Londres", 51.5074, -0.1278),
    "Europe/Brussels": ("Bruxelles", 50.8503, 4.3517), "Europe/Berlin": ("Berlin", 52.52, 13.405),
    "Europe/Madrid": ("Madrid", 40.4168, -3.7038), "Europe/Rome": ("Rome", 41.9028, 12.4964),
    "Europe/Zurich": ("Zurich", 47.3769, 8.5417), "Europe/Lisbon": ("Lisbonne", 38.7223, -9.1393),
    "America/New_York": ("New York", 40.7128, -74.006), "America/Toronto": ("Toronto", 43.6532, -79.3832),
    "America/Montreal": ("Montréal", 45.5019, -73.5674), "America/Los_Angeles": ("Los Angeles", 34.0522, -118.2437),
    "Africa/Casablanca": ("Casablanca", 33.5731, -7.5898), "Africa/Algiers": ("Alger", 36.7538, 3.0588),
    "Africa/Tunis": ("Tunis", 36.8065, 10.1815), "Asia/Tokyo": ("Tokyo", 35.6762, 139.6503),
    "Australia/Sydney": ("Sydney", -33.8688, 151.2093), "UTC": ("Greenwich", 51.4769, 0.0),
}
DEFAUT_VILLE = VILLES["Europe/Paris"]


@dataclass
class Lieu:
    nom: str
    latitude: float
    longitude: float
    approximatif: bool


@dataclass
class Fonction:
    enabled: bool = True
    provider: str = "auto"
    ttl_s: int = 900


@dataclass
class Saint:
    enabled: bool = True
    fichier: str = "/etc/secubox/ephemeride/saints.json"


@dataclass
class Obs:
    enabled: bool = True


@dataclass
class Config:
    enabled: bool = True
    timezone: str = "Europe/Paris"
    format_24h: bool = True
    nom_lieu: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    meteo: Fonction = field(default_factory=lambda: Fonction(ttl_s=900))
    air: Fonction = field(default_factory=lambda: Fonction(ttl_s=1800))
    saint: Saint = field(default_factory=Saint)
    observations: Obs = field(default_factory=Obs)

    def fuseau(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            log.warning("fuseau %r inconnu, repli sur Europe/Paris", self.timezone)
            return ZoneInfo("Europe/Paris")

    def lieu(self) -> Lieu:
        lat, lon = self.latitude, self.longitude
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and not isinstance(lat, bool) \
                and -90 <= lat <= 90 and -180 <= lon <= 180:
            return Lieu(self.nom_lieu or "", float(lat), float(lon), False)
        nom, la, lo = VILLES.get(self.fuseau().key, DEFAUT_VILLE)
        return Lieu(self.nom_lieu or nom, la, lo, True)


def _fonction(t: dict, defaut: Fonction) -> Fonction:
    ttl = t.get("ttl_s", defaut.ttl_s)
    return Fonction(bool(t.get("enabled", defaut.enabled)), str(t.get("provider", defaut.provider)),
                    ttl if isinstance(ttl, int) and not isinstance(ttl, bool) and 60 <= ttl <= 86400 else defaut.ttl_s)


def _lire(chemin: Path) -> dict:
    try:
        with open(chemin, "rb") as f:
            return tomllib.load(f).get("ephemeride", {})
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as e:
        log.warning("configuration %s illisible (%s) : valeurs par défaut", chemin, e)
        return {}


def charger(chemin: Optional[Path] = None, defaut: Optional[Path] = None) -> Config:
    brut = _lire(chemin or CONF) or _lire(defaut or CONF_DEFAUT)
    c = Config()
    c.enabled = bool(brut.get("enabled", c.enabled))
    c.timezone = str(brut.get("timezone", c.timezone))
    c.format_24h = bool(brut.get("format_24h", c.format_24h))
    lieu = brut.get("location", {}) if isinstance(brut.get("location"), dict) else {}
    c.nom_lieu = str(lieu.get("name", "") or "")
    c.latitude, c.longitude = lieu.get("latitude"), lieu.get("longitude")
    c.meteo = _fonction(brut.get("weather", {}) if isinstance(brut.get("weather"), dict) else {}, c.meteo)
    c.air = _fonction(brut.get("air_quality", {}) if isinstance(brut.get("air_quality"), dict) else {}, c.air)
    s = brut.get("saint", {}) if isinstance(brut.get("saint"), dict) else {}
    c.saint = Saint(bool(s.get("enabled", True)), str(s.get("file", c.saint.fichier)))
    o = brut.get("observations", {}) if isinstance(brut.get("observations"), dict) else {}
    c.observations = Obs(bool(o.get("enabled", True)))
    return c

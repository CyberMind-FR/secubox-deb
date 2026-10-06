# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: météo et qualité de l'air. Deux abstractions (WeatherProvider, AirQualityProvider) et un cache
de fichier : la carte fonctionne sans Internet (dernières données connues, marquées périmées) et ne martèle jamais le réseau.

Vie privée : les coordonnées envoyées au fournisseur sont ARRONDIES à 0,01° (~1 km). TLS vérifié (valeurs par défaut d'urllib)."""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional, Protocol

log = logging.getLogger("ephemeride")

DELAI_S = 4.0
OCTETS_MAX = 200_000
RECUL_ECHEC_S = 300
CACHE = Path(os.environ.get("SECUBOX_EPH_CACHE", "/var/lib/secubox/ephemeride/cache.json"))


class FournisseurIndisponible(Exception):
    """Le fournisseur ne répond pas ou répond n'importe quoi ; le message ne contient jamais de détail technique."""


@dataclass
class Meteo:
    temperature_c: float
    condition: str
    icone: str
    code: int
    humidite: Optional[int] = None
    vent_kmh: Optional[float] = None
    observe_a: Optional[str] = None


@dataclass
class Air:
    indice: int
    niveau: str
    polluant_principal: Optional[str] = None
    observe_a: Optional[str] = None


class WeatherProvider(Protocol):
    def obtenir(self, latitude: float, longitude: float) -> Meteo: ...


class AirQualityProvider(Protocol):
    def obtenir(self, latitude: float, longitude: float) -> Air: ...


def _lire_http(url: str, delai: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "secubox-ephemeride", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=delai) as r:               # noqa: S310 — https en dur, hôte fixe
        return json.loads(r.read(OCTETS_MAX).decode("utf-8"))


_WMO = [((0,), "Ciel dégagé", "soleil"), ((1, 2), "Peu nuageux", "nuage-soleil"), ((3,), "Couvert", "nuage"),
        ((45, 48), "Brouillard", "brouillard"), ((51, 53, 55, 56, 57), "Bruine", "pluie"),
        ((61, 63, 65, 66, 67), "Pluie", "pluie"), ((71, 73, 75, 77), "Neige", "neige"),
        ((80, 81, 82), "Averses", "pluie"), ((85, 86), "Averses de neige", "neige"), ((95, 96, 99), "Orage", "orage")]


def condition_wmo(code) -> tuple:
    for codes, texte, icone in _WMO:
        if code in codes:
            return texte, icone
    return "Conditions variables", "nuage"


def niveau_air(aqi: float) -> str:
    for borne, nom in ((20, "Bon"), (40, "Correct"), (60, "Moyen"), (80, "Médiocre"), (100, "Mauvais")):
        if aqi <= borne:
            return nom
    return "Très mauvais"


def _coord(lat: float, lon: float) -> str:
    return f"latitude={lat:.2f}&longitude={lon:.2f}"


class OpenMeteoMeteo:
    URL = "https://api.open-meteo.com/v1/forecast?{c}&current=temperature_2m,relative_humidity_2m,weather_code,wind_speed_10m&timezone=auto"

    def __init__(self, lecteur: Callable[[str, float], dict] = _lire_http, delai: float = DELAI_S):
        self.lecteur, self.delai = lecteur, delai

    def obtenir(self, latitude: float, longitude: float) -> Meteo:
        try:
            cur = self.lecteur(self.URL.format(c=_coord(latitude, longitude)), self.delai)["current"]
            code = int(cur["weather_code"])
            texte, icone = condition_wmo(code)
            return Meteo(round(float(cur["temperature_2m"]), 1), texte, icone, code,
                         int(cur["relative_humidity_2m"]) if cur.get("relative_humidity_2m") is not None else None,
                         round(float(cur["wind_speed_10m"]), 1) if cur.get("wind_speed_10m") is not None else None,
                         cur.get("time"))
        except Exception as e:                    # noqa: BLE001 — réseau, JSON, clé absente : même issue pour l'appelant
            log.warning("météo indisponible : %s", e)
            raise FournisseurIndisponible("météo indisponible") from None


class OpenMeteoAir:
    URL = "https://air-quality-api.open-meteo.com/v1/air-quality?{c}&current=european_aqi,pm10,pm2_5&timezone=auto"

    def __init__(self, lecteur: Callable[[str, float], dict] = _lire_http, delai: float = DELAI_S):
        self.lecteur, self.delai = lecteur, delai

    def obtenir(self, latitude: float, longitude: float) -> Air:
        try:
            cur = self.lecteur(self.URL.format(c=_coord(latitude, longitude)), self.delai)["current"]
            aqi = round(float(cur["european_aqi"]))
            p25, p10 = cur.get("pm2_5"), cur.get("pm10")
            polluant = None
            if p25 is not None and p10 is not None:
                polluant = "PM2.5" if float(p25) / 25.0 >= float(p10) / 50.0 else "PM10"
            return Air(aqi, niveau_air(aqi), polluant, cur.get("time"))
        except Exception as e:                    # noqa: BLE001
            log.warning("qualité de l'air indisponible : %s", e)
            raise FournisseurIndisponible("qualité de l'air indisponible") from None


@dataclass
class Resultat:
    etat: str                     # frais | perime | indisponible
    donnees: Optional[dict]
    ts: Optional[float]           # instant de la dernière mesure réussie


class Cache:
    """Cache JSON par clé. Frais pendant ttl ; au-delà, le fournisseur est réinterrogé, et s'il échoue l'ancienne valeur
    est servie « périmée ». Après un échec, on ne réessaie pas avant RECUL_ECHEC_S : le réseau n'est pas martelé."""

    def __init__(self, chemin: Path = CACHE):
        self.chemin = Path(chemin)
        self._verrou = threading.Lock()

    def _lire(self) -> dict:
        try:
            brut = json.loads(self.chemin.read_text(encoding="utf-8"))
            return brut if isinstance(brut, dict) else {}
        except (OSError, ValueError):
            return {}

    def _ecrire(self, tout: dict) -> None:
        try:
            self.chemin.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.chemin.parent, prefix=".cache-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(tout, f)
            os.replace(tmp, self.chemin)
        except OSError as e:
            log.warning("cache non écrit : %s", e)

    def lire(self, cle: str, ttl: float, maintenant: Optional[float] = None) -> Resultat:
        """Sans réseau : ce que le cache sait, marqué frais ou périmé."""
        now = time.time() if maintenant is None else maintenant
        e = self._lire().get(cle)
        if not isinstance(e, dict) or not isinstance(e.get("donnees"), dict):
            return Resultat("indisponible", None, None)
        return Resultat("frais" if now - e.get("ts", 0) < ttl else "perime", e["donnees"], e.get("ts"))

    def obtenir(self, cle: str, ttl: float, fetch: Callable[[], dict], maintenant: Optional[float] = None) -> Resultat:
        now = time.time() if maintenant is None else maintenant
        with self._verrou:
            tout = self._lire()
            e = tout.get(cle) if isinstance(tout.get(cle), dict) else {}
            donnees = e.get("donnees") if isinstance(e.get("donnees"), dict) else None
            if donnees is not None and now - e.get("ts", 0) < ttl:
                return Resultat("frais", donnees, e.get("ts"))
            if e.get("echec") is not None and now - e["echec"] < RECUL_ECHEC_S:
                return Resultat("perime", donnees, e.get("ts")) if donnees is not None else Resultat("indisponible", None, None)
            try:
                neuf = fetch()
            except FournisseurIndisponible:
                e["echec"] = now
                tout[cle] = e
                self._ecrire(tout)
                return Resultat("perime", donnees, e.get("ts")) if donnees is not None else Resultat("indisponible", None, None)
            tout[cle] = {"ts": now, "donnees": neuf, "echec": None}
            self._ecrire(tout)
            return Resultat("frais", neuf, now)


def vers_dict(x) -> dict:
    return asdict(x)

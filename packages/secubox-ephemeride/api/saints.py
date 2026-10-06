# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: saint du jour. Un fournisseur est une interface (SaintProvider) : données livrées,
fichier JSON de l'administrateur par-dessus, et — plus tard — une API. Rien ici n'exige le réseau ni ne lève d'exception."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import List, Optional, Protocol

log = logging.getLogger("ephemeride")

_ICI = Path(__file__).resolve().parent
DONNEES = next((p for p in (Path(os.environ.get("SECUBOX_EPH_DATA", "")) / "saints.json",
                            Path("/usr/share/secubox/ephemeride/saints.json"),
                            _ICI.parent / "data" / "saints.json") if p.is_file()), _ICI.parent / "data" / "saints.json")


@dataclass
class Saint:
    nom: str
    description: str = ""
    citation: Optional[str] = None
    image: Optional[str] = None


class SaintProvider(Protocol):
    def pour(self, jour: date) -> List[Saint]: ...


def _cle(jour: date) -> str:
    return f"{jour.month:02d}-{jour.day:02d}"


class FichierSaints:
    """Saints lus dans un JSON {"saints": {"MM-JJ": [{"nom", "description", "citation"?, "image"?}]}}. Fichier absent ou
    corrompu : liste vide (et un avertissement), jamais d'exception. Une entrée invalide est ignorée seule."""

    def __init__(self, chemin: Path):
        self.chemin = Path(chemin)
        self._cache: Optional[dict] = None
        self._mtime = None

    def _charger(self) -> dict:
        try:
            m = self.chemin.stat().st_mtime
        except OSError:
            return {}
        if self._cache is not None and m == self._mtime:
            return self._cache
        try:
            brut = json.loads(self.chemin.read_text(encoding="utf-8"))
            tous = brut.get("saints", {}) if isinstance(brut, dict) else {}
            if not isinstance(tous, dict):
                tous = {}
        except (OSError, ValueError) as e:
            log.warning("fichier de saints %s illisible : %s", self.chemin, e)
            tous = {}
        self._cache, self._mtime = tous, m
        return tous

    def pour(self, jour: date) -> List[Saint]:
        sorties = []
        for e in self._charger().get(_cle(jour), []):
            if isinstance(e, dict) and isinstance(e.get("nom"), str) and e["nom"].strip():
                sorties.append(Saint(e["nom"].strip(), str(e.get("description", "")), e.get("citation") or None,
                                     e.get("image") or None))
        return sorties


class Chaine:
    """Premier fournisseur qui répond non vide, jour par jour ; un fournisseur qui échoue est sauté."""

    def __init__(self, fournisseurs):
        self.fournisseurs = list(fournisseurs)

    def pour(self, jour: date) -> List[Saint]:
        for f in self.fournisseurs:
            try:
                r = f.pour(jour)
            except Exception as e:                    # noqa: BLE001 — un fournisseur tiers ne doit jamais casser la carte
                log.warning("fournisseur de saints en échec : %s", e)
                continue
            if r:
                return r
        return []


def fournisseur(fichier: Optional[Path] = None) -> Chaine:
    chaine = []
    if fichier is not None:
        chaine.append(FichierSaints(fichier))
    chaine.append(FichierSaints(DONNEES))
    return Chaine(chaine)

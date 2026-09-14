# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Voice — PROFILS VOCAUX (#1287).

« Billets → voix chaleureuse. Alertes Sentinel → voix neutre. Radio → animateur. »

C'est le détail qui fait qu'un système parle au lieu de lire. Il mérite donc d'être
une DONNÉE, pas du code : un module qui veut sa propre voix la déclare, et personne
n'a besoin de modifier ce fichier pour l'ajouter.

DEUX SOURCES, DANS CET ORDRE :
  1. les profils déclarés dans `/etc/secubox/voice.toml` — l'opérateur a le dernier
     mot sur la voix de sa box ;
  2. le champ `profils` des manifestes `/usr/share/secubox/capabilities.d/*.json`,
     qui permet à un paquet d'arriver avec sa voix.

UN PROFIL INCONNU N'EST JAMAIS SILENCIEUSEMENT REMPLACÉ. On rend le profil par
défaut ET on le dit à l'appelant : une alerte de sécurité lue par la voix
d'animateur serait une erreur qu'il vaut mieux voir passer qu'ignorer.
"""
from __future__ import annotations

import glob
import json
import re
from dataclasses import dataclass
from typing import Optional

from secubox_core.logger import get_logger

log = get_logger("voice")

CAP_DIR = "/usr/share/secubox/capabilities.d"

# Un nom de profil sert à composer un nom de fichier de voix : on le contraint
# strictement, ici, une fois, plutôt que d'espérer que chaque appelant soit sage.
_NOM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


@dataclass(frozen=True)
class Profil:
    nom: str          # « billets », « sentinel »…
    voix: str         # le modèle de voix à employer
    libelle: str      # ce que l'interface affiche


def _valide(nom: str) -> bool:
    return bool(_NOM_RE.match(nom or ""))


class Profils:
    """Résout une SOURCE (un service, un ton) en une VOIX concrète."""

    def __init__(self, cfg: dict) -> None:
        self.defaut = str(cfg.get("voix_defaut", "lexie-fr"))
        self._table: dict[str, Profil] = {}
        self._charge_manifestes()
        self._charge_config(cfg)        # après : la config gagne (cf. docstring)

    # — chargement ————————————————————————————————————————————————————

    def _pose(self, nom: str, voix: str, libelle: str, origine: str) -> None:
        if not _valide(nom) or not _valide(voix):
            log.warning("profil vocal ignoré (nom ou voix hors format) : "
                        "%r → %r, depuis %s", nom, voix, origine)
            return
        self._table[nom] = Profil(nom=nom, voix=voix, libelle=libelle or nom)

    def _charge_manifestes(self) -> None:
        for f in sorted(glob.glob(f"{CAP_DIR}/*.json")):
            try:
                doc = json.loads(open(f, encoding="utf-8").read())
            except (OSError, ValueError) as e:
                log.warning("manifeste illisible %s : %s", f, e)
                continue
            for nom, p in (doc.get("profils") or {}).items():
                if isinstance(p, dict):
                    self._pose(nom, str(p.get("voix", "")),
                               str(p.get("libelle", "")), f)

    def _charge_config(self, cfg: dict) -> None:
        for nom, p in (cfg.get("profils") or {}).items():
            if isinstance(p, dict):
                self._pose(nom, str(p.get("voix", "")),
                           str(p.get("libelle", "")), "voice.toml")

    # — résolution ————————————————————————————————————————————————————

    def resoud(self, nom: Optional[str]) -> tuple[str, Optional[str]]:
        """Rend (voix, avertissement). L'avertissement n'est pas décoratif : il
        remonte jusqu'à l'appelant pour qu'un profil absent se remarque."""
        if not nom:
            return self.defaut, None
        p = self._table.get(nom)
        if p:
            return p.voix, None
        if _valide(nom):
            return self.defaut, (
                f"Profil vocal « {nom} » inconnu — voix par défaut employée. "
                f"Déclarez-le dans voice.toml ou dans le manifeste du module.")
        return self.defaut, f"Profil vocal « {nom} » hors format — ignoré."

    def liste(self) -> list[dict]:
        return [{"nom": p.nom, "voix": p.voix, "libelle": p.libelle}
                for p in sorted(self._table.values(), key=lambda x: x.nom)]

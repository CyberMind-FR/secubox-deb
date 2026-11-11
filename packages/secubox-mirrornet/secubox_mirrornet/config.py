# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Chemins et réglages de secubox-mirrornet (#3645, #3647). Chemins surchargeables pour les tests seulement."""
from __future__ import annotations

import logging
import os
import tomllib
from pathlib import Path
from typing import Any, Dict

ETAT = Path(os.environ.get("SBX_MIRRORNET_ETAT", "/var/lib/secubox-mirrornet"))
BASE = Path(os.environ.get("SBX_MIRRORNET_DB", str(ETAT / "mirrornet.db")))
CONF = Path(os.environ.get("SBX_MIRRORNET_CONF", "/etc/secubox/mirrornet.toml"))
EXPORT = Path(os.environ.get("SBX_MIRRORNET_EXPORT", "/var/lib/secubox/annuaire/mirrornet-export.json"))
ANNUAIRE_SOCK = os.environ.get("SBX_MIRRORNET_ANNUAIRE_SOCK", "/run/secubox/annuaire.sock")


def _objets_defaut() -> Path:
    """Objets des jeux de données (#3653) : sur /data quand le paquet y a préparé le dossier (jamais la racine pleine
    d'une MOCHAbin, R7), sinon sous l'état du service."""
    donnees = Path("/data/mirrornet/objets")
    return donnees if donnees.is_dir() else ETAT / "objets"


OBJETS = Path(os.environ["SBX_MIRRORNET_OBJETS"]) if os.environ.get("SBX_MIRRORNET_OBJETS") else _objets_defaut()
PORT_MAILLAGE = int(os.environ.get("SBX_MIRRORNET_PORT_MAILLAGE", "8799"))

DEFAUTS: Dict[str, Any] = {"confiance_min": "LIMITED", "grace_s": 432000, "intervalle_s": 60,
                           "taille_max_mo": 256, "garder": 3, "reserve_mo": 1024,
                           "service_simultane": 4, "certif_s": 900}
_NIVEAUX = ("OBSERVER", "LIMITED", "PARTNER", "TRUSTED")


def reglages() -> Dict[str, Any]:
    """Réglages effectifs : un fichier absent, illisible ou une valeur hors bornes retombent sur le défaut."""
    r = dict(DEFAUTS)
    try:
        with open(CONF, "rb") as f:
            d = tomllib.load(f)
    except FileNotFoundError:
        return r
    except (OSError, tomllib.TOMLDecodeError) as e:
        # Jamais en silence : un seuil de confiance ignoré présenterait des offres que l'administrateur a exclues.
        logging.getLogger("secubox-mirrornet").warning("%s illisible (%s) : réglages par défaut", CONF, e)
        return r
    c = (d.get("catalogue") or {}).get("confiance_min")
    if c in _NIVEAUX:
        r["confiance_min"] = c
    g = (d.get("abonnements") or {}).get("grace_s")
    if type(g) is int and 0 <= g <= 90 * 86400:
        r["grace_s"] = g
    i = (d.get("synchro") or {}).get("intervalle_s")
    if type(i) is int and 10 <= i <= 3600:
        r["intervalle_s"] = i
    donnees = d.get("donnees") or {}
    for cle, mini, maxi in (("taille_max_mo", 1, 256), ("garder", 1, 50), ("reserve_mo", 0, 100000)):
        v = donnees.get(cle)
        if type(v) is int and mini <= v <= maxi:
            r[cle] = v
    espace = d.get("espace") if isinstance(d.get("espace"), dict) else {}
    for cle, mini, maxi in (("service_simultane", 1, 64), ("certif_s", 60, 86400)):
        v = espace.get(cle)
        if type(v) is int and mini <= v <= maxi:
            r[cle] = v
    return r

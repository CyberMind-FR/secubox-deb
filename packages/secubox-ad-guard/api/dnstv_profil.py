# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: profil de base et agrégation des règles du mode « auto » (#1959).

Le profil effectif d'un nouvel appareil = la GRAINE (`lists/profil-tv-base.txt`, les domaines validés sur deux TV réelles) + le profil AGRÉGÉ : les domaines
CONFIRMÉS PAR L'ADMINISTRATEUR sur au moins `min_appareils` appareils distincts. Les règles issues du profil lui-même (origine `auto`, motif « profil… »)
ne comptent JAMAIS pour l'agrégation : sinon la graine se renforcerait toute seule. Les appareils existants reçoivent les nouveaux domaines agrégés comme
CANDIDATS, jamais comme règles actives. Module sans entrée/sortie réseau ; fichiers lus sans suivre les liens symboliques.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from . import dnstv, dnstv_regles
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_regles

FICHIER_AGREGE = "profil-agrege.json"
DOSSIER_LISTES_PAQUET = Path(__file__).resolve().parents[1] / "lists"        # arbre de sources ; le paquet installé utilise dnstv.DOSSIER_LISTES
SCORE_AGREGE = 90


def graine(dossier_listes: Optional[Path] = None) -> List[str]:
    d = dossier_listes or (dnstv.DOSSIER_LISTES if (dnstv.DOSSIER_LISTES / "profil-tv-base.txt").is_file() else DOSSIER_LISTES_PAQUET)
    f = d / "profil-tv-base.txt"
    return dnstv.lire_liste(f)[0] if f.is_file() else []


def _confirme_par_admin(r: dict) -> bool:
    h = (r.get("historique") or [{}])[-1]
    return r["etat"] == "confirme" and h.get("vers") == "confirme" and h.get("origine") == "admin"


def agreger(regles, min_appareils: int = 2) -> Dict[str, dict]:
    """domaine -> {"appareils": [...], "maj": dernière confirmation} pour les domaines confirmés PAR L'ADMINISTRATEUR sur ≥ `min_appareils` appareils."""
    par: Dict[str, Dict[str, int]] = {}
    for r in regles.liste():
        if _confirme_par_admin(r):
            par.setdefault(r["domaine"], {})[r["appareil"]] = r["historique"][-1]["ts"]
    return {d: {"appareils": sorted(a), "maj": max(a.values())} for d, a in par.items() if len(a) >= max(1, min_appareils)}


def profil_effectif(graine_: List[str], agrege: Dict[str, dict]) -> List[Tuple[str, str]]:
    """[(domaine, motif)] : la graine d'abord, puis les domaines agrégés qui n'y sont pas."""
    out = [(d, "profil de base") for d in graine_]
    connus = set(graine_)
    for d, e in sorted(agrege.items()):
        if d not in connus:
            out.append((d, f"profil agrégé ({len(e['appareils'])} appareils)"))
    return out


def equiper(regles, appareil: str, profil: List[Tuple[str, str]], maintenant: int) -> int:
    """Règles CONFIRMÉES (origine `auto`) pour un appareil ajouté automatiquement ; idempotent. Rend le nombre de règles créées."""
    n = 0
    for domaine, motif in profil:
        r = regles.proposer(appareil, domaine, 100, "faible", maintenant, origine="auto", motif=motif)
        if r is None:
            continue
        regles.transiter(r["id"], "essai", "auto", motif, maintenant)
        regles.transiter(r["id"], "confirme", "auto", motif, maintenant)
        n += 1
    return n


def candidats_agreges(regles, agrege: Dict[str, dict], appareils_auto: List[str], maintenant: int) -> int:
    """Propose (CANDIDAT, jamais actif) aux appareils qui n'ont pas encore la règle un domaine confirmé ailleurs. Un domaine déjà connu d'un appareil
    (y compris rejeté ou retiré) n'est pas reproposé. Rend le nombre de candidats créés."""
    n = 0
    for domaine, e in sorted(agrege.items()):
        for app in appareils_auto:
            if app in e["appareils"]:
                continue
            autres = len(e["appareils"])
            if regles.proposer(app, domaine, SCORE_AGREGE, "faible", maintenant, origine="auto", motif=f"confirmé sur {autres} autres appareils") is not None:
                n += 1
    return n


def _valider_agrege(brut) -> Dict[str, dict]:
    if not isinstance(brut, dict):
        return {}
    out: Dict[str, dict] = {}
    for d, e in brut.items():
        if dnstv.valider_domaine(d) != d or not isinstance(e, dict):
            return {}                                    # une entrée invalide invalide tout le fichier : jamais de contenu partiellement digne de confiance
        apps, maj = e.get("appareils"), e.get("maj", 0)
        if not isinstance(apps, list) or not apps or any(not isinstance(a, str) or dnstv_regles.slug(a) != a for a in apps) \
                or not isinstance(maj, int) or isinstance(maj, bool) or maj < 0:
            return {}
        out[d] = {"appareils": sorted(set(apps)), "maj": maj}
    return out


def charger_agrege(dossier: Optional[Path] = None) -> Dict[str, dict]:
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER_AGREGE
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return _valider_agrege(json.loads(h.read(2 * 1024 * 1024)))
    except (OSError, ValueError):
        return {}


def ecrire_agrege(agrege: Dict[str, dict], dossier: Optional[Path] = None) -> None:
    valide = _valider_agrege(agrege)
    if agrege and not valide:
        raise dnstv_regles.ErreurRegle("profil agrégé invalide")
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".agrege.")
    with os.fdopen(fd, "w", encoding="utf-8") as h:
        json.dump(valide, h, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, d / FICHIER_AGREGE)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: DPI :: étiquettes d'ad-guard pour les destinations non classées (#1960).

Le DPI ne classe pas toujours un nom (destination vue sans SNI, service inconnu de `rules.json`) : il le met dans « unknown ». Ce module y ajoute une ÉTIQUETTE tirée de la
connaissance d'ad-guard — organisation et type (`services.txt`), catégorie publicité / pistage / télémétrie / réseaux sociaux (listes) — SANS jamais exécuter de code d'ad-guard :
il lit ses FICHIERS DE DONNÉES, en lecture seule. Une règle du DPI qui connaît le nom GAGNE toujours. L'étiquette porte sa source (« ad-guard ») et dit « d'après » : un suffixe
partagé entre publicité et contenu peut se tromper. Aucune écriture, aucun effet de bord ; données absentes ⇒ comportement inchangé.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

TYPES_SERVICE = ("contenu", "publicite", "mesure_audience", "analytique", "qualite_video", "cdn", "connectivite", "systeme", "inconnu")
CATEGORIES = ("advertising", "tracking", "telemetry", "social")
LECTURE_MAX = 4 * 1024 * 1024

LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAINE_RE = re.compile(rf"^(?:{LABEL}\.)+[a-z0-9-]{{2,63}}$")
IP_V4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normaliser(hote) -> Optional[str]:
    """Un nom de domaine en minuscules sans point final, ou None (hôte absent, adresse IP, caractère inattendu, trop long). Jamais d'exception."""
    if not isinstance(hote, str):
        return None
    h = hote.strip().lower().rstrip(".")
    if not h or len(h) > 253 or IP_V4_RE.match(h) or not DOMAINE_RE.match(h):
        return None
    return h


def _lire(chemin: Path) -> str:
    try:
        with open(chemin, "rb") as h:
            return h.read(LECTURE_MAX).decode("utf-8", "replace")
    except OSError:
        return ""


def charger_services(chemin: Path) -> List[Tuple[str, str, str]]:
    """Lignes `suffixe  organisation  type` (organisation : `_` = espace). Une ligne invalide est ignorée. Plus long suffixe d'abord."""
    out = []
    for ligne in _lire(Path(chemin)).splitlines():
        brut = ligne.split("#", 1)[0].split()
        if len(brut) == 3 and brut[2] in TYPES_SERVICE:
            d = normaliser(brut[0])
            if d:
                out.append((d, brut[1].replace("_", " "), brut[2]))
    return sorted(out, key=lambda x: -len(x[0]))


def charger_listes(dossier: Path) -> Dict[str, str]:
    """domaine -> catégorie, d'après les listes `advertising|tracking|telemetry|social.txt` (un domaine par ligne, `#` commence un commentaire)."""
    out: Dict[str, str] = {}
    for cat in CATEGORIES:
        for ligne in _lire(Path(dossier) / f"{cat}.txt").splitlines():
            d = normaliser(ligne.split("#", 1)[0].strip())
            if d and d not in out:
                out[d] = cat
    return out


class Etiqueteur:
    def __init__(self, services: List[Tuple[str, str, str]], listes: Dict[str, str]):
        self._services: Dict[str, Tuple[str, str]] = {s: (org, typ) for s, org, typ in services}
        self._listes = dict(listes)

    @classmethod
    def depuis_dossier(cls, dossier: Path) -> "Etiqueteur":
        d = Path(dossier)
        return cls(charger_services(d / "services.txt"), charger_listes(d))

    @property
    def vide(self) -> bool:
        return not self._services and not self._listes

    def etiqueter(self, hote) -> dict:
        h = normaliser(hote)
        if h is None or self.vide:
            return {}
        org = typ = cat = ""
        parties = h.split(".")
        for i in range(len(parties) - 1):                      # du nom complet vers ses parents : le plus long suffixe d'abord
            s = ".".join(parties[i:])
            if not org and s in self._services:
                org, typ = self._services[s]
            if not cat and s in self._listes:
                cat = self._listes[s]
            if org and cat:
                break
        if not (org or cat):
            return {}
        return {"organisation": org, "type": typ, "categorie": cat, "source": "ad-guard"}


def enrichir_usage(usage, etiqueteur: Etiqueteur, classer_dpi: Callable[[str], dict]):
    """Copie de `usage` où chaque entrée de `unknown` que le DPI ne connaît pas porte `etiquette`, plus `adguard: {etiquetes, total}`.
    Ne retire ni ne déplace rien. Sans données d'ad-guard, sans liste `unknown` ou si `usage` n'est pas un dict : rendu tel quel."""
    if not isinstance(usage, dict) or etiqueteur.vide or not isinstance(usage.get("unknown"), list):
        return usage
    r = copy.deepcopy(usage)
    n = 0
    for e in r["unknown"]:
        if not isinstance(e, dict) or not isinstance(e.get("name"), str):
            continue
        if classer_dpi(e["name"]):                              # une règle du DPI qui connaît le nom GAGNE
            continue
        et = etiqueteur.etiqueter(e["name"])
        if et:
            e["etiquette"] = et
            n += 1
    r["adguard"] = {"etiquetes": n, "total": len(r["unknown"])}
    return r

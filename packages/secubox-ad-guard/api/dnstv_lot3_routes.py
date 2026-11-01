# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes `/adblock-tv/protection/*` du lot 3 SBX TV PRIVACY (#3374).

Gardes : lecture d'une donnée par appareil `require_lecture_nominative` (administrateur réel ou porteur délégué du pilotage) ;
écriture et export `require_jwt` ; SEULE exception, la route lambda « Ça ne marche plus ? Je débloque » (`/protection/usager/*`),
en `require_personne` et bornée (pause minutée ou retour en observation ; jamais de durcissement, de liste ni d'historique).
Ce routeur est inclus dans celui de `dnstv_routes` (préfixe `/adblock-tv`).
"""
from __future__ import annotations

import csv
import io
import time
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

try:
    from . import dnstv, dnstv_analyse, dnstv_appareils
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_analyse, dnstv_appareils
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt

router = APIRouter(tags=["adblock-tv-protection"])


def est_admin_reel(p) -> bool:
    """Administrateur réel (délégué à `dnstv_routes`, que les tests surchargent)."""
    return bool(_r.est_admin_reel(p))


def _admin(lecteur) -> bool:
    return isinstance(lecteur, dict) and not lecteur.get("tableau_de_bord") and est_admin_reel(lecteur)


# ── analyseur ────────────────────────────────────────────────────────────────────────────────────────

def _pour_lecteur(e: dict) -> dict:
    """Vue d'un lecteur qui n'est pas administrateur réel (porteur délégué) : MAC tronquée, sans adresses, observation au jour."""
    d = {k: v for k, v in e.items() if k not in ("ips", "precision")}
    d["mac"] = dnstv_appareils.mac_courte(e["mac"]) if e.get("mac") else None
    for k in ("derniere_observation", "premiere_observation"):
        d[k] = dnstv._jour(e[k]) if e.get(k) else None
    return d


def _filtres(fenetre, mac, categorie, decision, source, confiance_min, confiance_max, q, domaine, racine) -> dict:
    return {"fenetre": fenetre, "macs": mac or [], "categories": categorie or [], "decisions": decision or [], "sources": source or [],
            "confiance_min": confiance_min, "confiance_max": confiance_max, "q": q, "domaine_exact": domaine, "racine_exacte": racine}


def _params(fenetre: str = "30j", mac: Optional[List[str]] = Query(None), categorie: Optional[List[str]] = Query(None),
            decision: Optional[List[str]] = Query(None), source: Optional[List[str]] = Query(None), confiance_min: int = 0,
            confiance_max: int = 100, q: Optional[str] = Query(None, max_length=64), domaine: Optional[str] = Query(None, max_length=253),
            racine: Optional[str] = Query(None, max_length=253)) -> dict:
    for liste in (mac, categorie, decision, source):
        if liste and len(liste) > 10:
            raise HTTPException(422, "10 valeurs au plus par filtre")
    return _filtres(fenetre, mac, categorie, decision, source, confiance_min, confiance_max, q, domaine, racine)


@router.get("/protection/analyse")
def analyse(f: dict = Depends(_params), agreger: str = "racine", decalage: int = 0, limite: int = 25,
            lecteur=Depends(_r.require_lecture_nominative)):
    """Analyseur côté serveur : métriques, agrégats (domaine, racine, catégorie, appareil) et une page de lignes (25 par défaut,
    200 au plus), filtres combinables. Lu dans le cache découpé du moteur AUTO ; aucun calcul lourd ni jeu complet dans la réponse."""
    try:
        res = dnstv_analyse.analyser(agreger=agreger, decalage=decalage, limite=limite, maintenant=int(time.time()), **f)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None
    if not _admin(lecteur):
        res["lignes"] = [_pour_lecteur(x) for x in res["lignes"]]
        for g in (res["agregats"] if agreger == "appareil" else []) + res["metriques"]["top_appareils"]:
            g["cle"] = dnstv_appareils.mac_courte(g["cle"]) if g.get("cle") else None
    res["categories"] = list(dnstv_analyse.dnstv_taxonomie.CATEGORIES)
    res["protegees"] = sorted(dnstv_analyse.dnstv_taxonomie.PROTEGEES)
    res["decisions"], res["fenetres"], res["agregations"] = list(dnstv_analyse.DECISIONS), list(dnstv_analyse.FENETRES), list(dnstv_analyse.AGREGATS)
    return res


def _cellule(v) -> str:
    """Cellule CSV neutralisée : une valeur qui commence par = + - @ (formule de tableur) est préfixée d'une apostrophe."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/protection/analyse.csv", dependencies=[Depends(require_jwt)])
def analyse_csv(f: dict = Depends(_params)):
    """Export CSV du résultat filtré (50 000 lignes au plus) : administrateur seulement."""
    try:
        lignes, _total, _g = dnstv_analyse.selection(maintenant=int(time.time()), **f)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["domaine", "appareil", "mac", "categorie", "source", "confiance", "requetes", "bloquees", "derniere", "premiere", "regle", "protegee"])
    for x in lignes:
        w.writerow([_cellule(v) for v in (x["domaine"], x.get("nom"), x.get("mac"), x["categorie"], x["source"], x["confiance"], x["requetes"],
                                          x["bloquees"], x.get("derniere_observation"), x.get("premiere_observation"), x.get("regle"), x["protegee"])])
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="tv-privacy-analyse.csv"'})


# ── événements récents agrégés ───────────────────────────────────────────────────────────────────────

def _noms_par_ip() -> dict:
    etat, _ = dnstv.lire_etat()
    return {c["ip"]: c["nom"] for c in etat.get("clients", [])}


@router.get("/protection/evenements")
def evenements(heures: int = 1, detail: bool = False, lecteur=Depends(_r.require_lecture_nominative)):
    """Requêtes récentes AGRÉGÉES par appareil × domaine réel (1 h ou 24 h) ; `detail=1` (administrateur) ajoute les lignes."""
    if detail and not _admin(lecteur):
        raise HTTPException(403, "détail ligne à ligne : administrateur requis")
    try:
        return dnstv_analyse.evenements_agreges(_r._magasin(), heures, int(time.time()), _noms_par_ip(), detail=detail)
    except dnstv_analyse.ErreurAnalyse as e:
        raise HTTPException(422, str(e)) from None



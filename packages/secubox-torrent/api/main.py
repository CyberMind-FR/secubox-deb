# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Torrent — API du module

CyberMind — https://cybermind.fr

CE FICHIER MANQUAIT, et l'agregateur le disait a chaque demarrage :

    torrent: main.py not found under /usr/lib/secubox/{torrent,torrent}/api/

Le module etait donc l'un des deux seuls, sur cent quatorze, a ne pas se
monter. L'ajouter corrige ce chargement ET porte la recherche d'index (#1032).
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, Query
from secubox_core.config import get_config

import nzb as _nzb
import recherche as _recherche

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("torrent")

app = FastAPI(title="SecuBox Torrent", version="2.4.0")
config = get_config("torrent") or {}


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/status")
async def status():
    """Etat du module. Public — ne dit rien de ce qui est recherche."""
    return {
        "module": "torrent",
        "version": app.version,
        "enabled": bool(config.get("enabled", True)),
        "running": True,
        "installed": True,
        "components": {"torrent": {"name": "torrent", "installed": True,
                                   "running": True}},
        "sources": sorted(_recherche.SOURCES),
    }


@app.get("/recherche")
async def chercher(q: str = Query("", max_length=200),
                   sources: str = Query("")):
    """Cherche dans les index publics et rend de VRAIES adresses magnet.

    PUBLIC, ET C'EST ASSUME : la page qui l'appelle l'est aussi, et cette
    recherche ne revele rien de la board — elle interroge des index publics.
    Ce qu'elle protege, c'est l'adresse du visiteur, qui n'atteint jamais les
    trackers puisque la requete part d'ici.

    `q` est borne a 200 caracteres : au-dela, ce n'est plus une recherche.
    """
    choix = [s.strip() for s in sources.split(",") if s.strip()] or None
    return await _recherche.cherche(q, choix)


@app.get("/sources")
async def sources():
    """Les index REELLEMENT interroges.

    L'interface lit cette liste au lieu de tenir la sienne. C'etait tout le
    probleme de la page d'origine : elle affichait sept pastilles — 1337x,
    EZTV, snowfl… — dont aucune n'etait interrogee, et les cocher ou les
    decocher ne changeait rien. Une liste servie par celui qui fait le travail
    ne peut pas mentir sur ce qu'il fait.
    """
    return {"sources": _recherche.liste_sources()}


@app.get("/nzb/indexeurs")
async def nzb_indexeurs():
    """Les indexeurs Usenet configures — JAMAIS leurs cles.

    `configure: false` n'est pas une erreur : c'est l'etat normal tant que
    personne n'a depose de cle. L'interface l'affiche tel quel, au lieu de
    fabriquer des resultats pour donner le change.
    """
    ix = _nzb.charge_indexeurs()
    return {"indexeurs": _nzb.indexeurs_publics(ix), "configure": bool(ix)}


@app.get("/nzb/recherche")
async def nzb_recherche(q: str = Query("", max_length=200)):
    """Cherche chez les indexeurs Newznab configures."""
    return await _nzb.cherche(q)

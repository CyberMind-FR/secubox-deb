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

RESTAURÉ PAR #1773 : la fusion aff481735 avait remis l'API Transmission en conteneur
de juin — plus de /recherche ni de /nzb, et un /status qui affirmait l'état.
Ce fichier ne porte QUE l'API hôte (état, recherche, Usenet) ; le moteur
WebTorrent (/list, /add, /files…) vit dans le LXC et nginx lui envoie le reste
de /api/v1/torrent/ (nginx/torrent-routes.conf).
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import json
import urllib.request

from fastapi import Depends, FastAPI, Query
from secubox_core.auth import require_jwt, require_lecture
from secubox_core.config import get_config

import nzb as _nzb
import recherche as _recherche

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("torrent")

app = FastAPI(title="SecuBox Torrent", version="2.4.9")
config = get_config("torrent") or {}

TORRENT_TOML = Path("/etc/secubox/torrent.toml")
MOTEUR_PORT = 8090


def _ip_moteur() -> str:
    """Adresse du LXC du moteur : [lxc].ip de torrent.toml, sinon le défaut
    posé par install-lxc.sh."""
    try:
        import tomllib
        return str(tomllib.loads(TORRENT_TOML.read_text()).get("lxc", {}).get("ip") or "10.100.0.160")
    except (OSError, ValueError, ImportError):
        return "10.100.0.160"


def _etat_moteur(delai: float = 1.5) -> dict | None:
    """Ce que le moteur dit de lui-même, ou None s'il ne répond pas (endormi
    par le sleeper, arrêté). Jamais d'exception : l'état doit toujours rendre."""
    url = f"http://{_ip_moteur()}:{MOTEUR_PORT}/api/v1/torrent/status"
    try:
        with urllib.request.urlopen(url, timeout=delai) as r:
            d = json.loads(r.read(65536))
            return d if isinstance(d, dict) else None
    except Exception:  # noqa: BLE001 — injoignable = endormi, pas une panne
        return None


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    """État du module, lecture LAN admise (#1256).

    HONNÊTE (#1773) : l'ancien rendait `running: True` en dur. On sonde le
    moteur (1,5 s) ; s'il répond, ses compteurs (actifs, place libre, WebRTC,
    bibliothèque) sont repris tels quels — c'est ce que lisent la page et la
    carte du Hall. Sinon `running: false, asleep: true` : le sleeper l'a
    endormi, ce n'est pas une panne, et on répond vite plutôt que 502."""
    moteur = _etat_moteur()
    base = {
        "module": "torrent",
        "version": app.version,
        "enabled": bool(config.get("enabled", True)),
        "installed": True,
        "running": moteur is not None,
        "asleep": moteur is None,
        "sources": sorted(_recherche.SOURCES),
    }
    base["components"] = {"torrent": {"name": "torrent", "installed": True,
                                      "running": moteur is not None}}
    return {**(moteur or {}), **base}


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


# /nzb/* : réservés à l'admin (#1773). Ils interrogent les indexeurs AVEC les
# clés de l'opérateur ; publics, n'importe qui dépensait son quota.
@app.get("/nzb/indexeurs", dependencies=[Depends(require_jwt)])
async def nzb_indexeurs():
    """Les indexeurs Usenet configures — JAMAIS leurs cles.

    `configure: false` n'est pas une erreur : c'est l'etat normal tant que
    personne n'a depose de cle. L'interface l'affiche tel quel, au lieu de
    fabriquer des resultats pour donner le change.
    """
    ix = _nzb.charge_indexeurs()
    return {"indexeurs": _nzb.indexeurs_publics(ix), "configure": bool(ix)}


@app.get("/nzb/recherche", dependencies=[Depends(require_jwt)])
async def nzb_recherche(q: str = Query("", max_length=200)):
    """Cherche chez les indexeurs Newznab configures."""
    return await _nzb.cherche(q)

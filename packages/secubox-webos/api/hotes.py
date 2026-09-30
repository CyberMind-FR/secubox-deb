# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webos — LES HÔTES QUE CETTE BOX SERT VRAIMENT (#1670).

Le Hall d'une autre box que gk2 (hall.gk3.secubox.in, relayé par le maillage)
réécrivait TOUS les services de référence vers son domaine : radio.gk3…,
metanews.gk3… — des noms que personne ne sert. Règle : une carte vise le service
de CETTE box s'il y est servi et joignable, sinon celui de la box de référence
(gk2) en repli.

« Servi et joignable » = un server_name exact de nginx sur cette box, dans le
domaine de la box, ET une réponse non-5xx par son chemin PUBLIC (DNS public →
relais éventuel → cette box). Un vhost présent mais jamais relayé n'est pas
local : la carte retomberait dans le vide. Calcul en tâche de fond, jamais dans
la requête (le script est bloquant dans la page).
"""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Iterable

SITES = Path("/etc/nginx/sites-enabled")
PERIODE_S = 600
DELAI_S = 5.0

_etat: dict = {"locaux": [], "t": 0.0}
_SN = re.compile(r"^\s*server_name\s+([^;]+);", re.M)


def candidats(textes: Iterable[str], domaine: str) -> list[str]:
    """server_name exacts se terminant par « .<domaine> » (ni joker ni regex)."""
    if not domaine:
        return []
    fin = "." + domaine.lower()
    vus: set[str] = set()
    for t in textes:
        for bloc in _SN.findall(t):
            for n in bloc.split():
                n = n.strip().lower()
                # « mood.* » : le service répond à tout domaine ; ici, au nôtre.
                if re.fullmatch(r"[a-z0-9-]+\.\*", n):
                    n = n[:-1] + domaine.lower()
                if n.endswith(fin) and "*" not in n and not n.startswith("~") and re.fullmatch(r"[a-z0-9.-]+", n):
                    vus.add(n)
    return sorted(vus)


def lire_sites(dossier: Path = SITES) -> list[str]:
    out = []
    try:
        for f in sorted(dossier.iterdir()):
            try:
                out.append(f.read_text(errors="ignore"))
            except OSError:
                continue
    except OSError:
        pass
    return out


def repond(code: int) -> bool:
    """Un code HTTP dit-il que le service est servi par son chemin public ?

    421 NE COMPTE PAS (#1714). C'est la réponse d'un frontal qui ne route pas ce
    nom — le relais de gk2 pour un service de gk3 jamais relayé, parce qu'à
    l'arrêt. Il était « < 500 », donc compté local : le Hall de gk3 envoyait
    peertube, photoprism, jellyfin, gitea, meet et ytsas vers des services
    morts au lieu de leur équivalent sur un autre nœud du maillage."""
    return code < 500 and code != 421


async def _joignable(nom: str) -> bool:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=DELAI_S, verify=False, follow_redirects=False) as cli:
            r = await cli.get(f"https://{nom}/", headers={"User-Agent": "secubox-webos-hotes"})
            return repond(r.status_code)
    except Exception:
        return False


async def recalculer(domaine: str) -> list[str]:
    noms = candidats(lire_sites(), domaine)
    oks = await asyncio.gather(*(_joignable(n) for n in noms))
    _etat["locaux"] = [n for n, ok in zip(noms, oks) if ok]
    _etat["t"] = time.time()
    return _etat["locaux"]


async def boucle(domaine_fn) -> None:
    while True:
        try:
            await recalculer(domaine_fn() or "")
        except Exception:
            pass
        await asyncio.sleep(PERIODE_S)


def locaux() -> list[str]:
    return list(_etat["locaux"])


def nom_noeud() -> str:
    """Le nom court de cette box : [global] hostname, sinon le nom d'hôte."""
    try:
        from secubox_core.config import get_config
        n = str(get_config("global").get("hostname", "") or "")
    except Exception:
        n = ""
    if not n:
        import socket
        n = socket.gethostname()
    n = n.split(".")[0].lower()
    return n if re.fullmatch(r"[a-z0-9-]{1,63}", n) else ""

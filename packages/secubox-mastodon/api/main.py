# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: Mastodon — API d'etat du module.

CyberMind — https://cybermind.fr

CE DEMON EST LEGER ET TOUJOURS JOIGNABLE, meme quand le conteneur est arrete.
C'est ce qui permet au panneau de distinguer « le module est absent » de
« l'instance est eteinte » — deux situations qui appellent des gestes
differents, et qu'un panneau muet confondrait.

Il ne parle jamais a Mastodon directement : tout passe par `mastodonctl`, seule
surface privilegiee du module. Un service qui manipulerait le conteneur
lui-meme aurait besoin de droits qu'il ne doit pas avoir.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from fastapi import Depends, FastAPI, HTTPException

try:
    from secubox_core import auth
except ImportError:  # tests isoles
    auth = None

CTL = shutil.which("mastodonctl") or "/usr/sbin/mastodonctl"
app = FastAPI(title="SecuBox Mastodon", docs_url=None, redoc_url=None)


# LA DEPENDANCE EST LA FONCTION ELLE-MEME, pas une fonction qui la RETOURNE.
#
# Le premier jet ecrivait `Depends(_exige_jwt)` ou `_exige_jwt()` se contentait
# de rendre `auth.require_jwt`. FastAPI appelait bien `_exige_jwt`, recevait un
# objet fonction... et s'arretait la. La verification n'a JAMAIS tourne : la
# surface entiere repondait 200 sans jeton, et rien ne le signalait — ni erreur,
# ni journal. Verifie sur la board avant correction.
#
# Sans le noyau, la surface est FERMEE, jamais ouverte : un module qui
# s'ouvrirait « faute de pouvoir verifier » offrirait ses actions a quiconque
# atteint la socket.
if auth is not None:
    _exige_jwt = auth.require_jwt
else:
    async def _exige_jwt():  # type: ignore[misc]
        raise HTTPException(503, "noyau d'authentification indisponible")


def _ctl(*args: str, delai: int = 20) -> dict:
    """Appelle mastodonctl SANS shell : les arguments restent des arguments.

    Le delai est borne — `install` rend la main tout de suite et travaille en
    arriere-plan, mais `status` interroge le reseau et pourrait attendre.
    """
    try:
        p = subprocess.run([CTL, *args], capture_output=True, text=True, timeout=delai)
    except FileNotFoundError:
        raise HTTPException(503, "mastodonctl absent")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "mastodonctl n'a pas repondu")
    sortie = (p.stdout or "").strip()
    try:
        return json.loads(sortie)
    except json.JSONDecodeError:
        # On rend la sortie BRUTE plutot qu'un message generique : « erreur
        # interne » n'a jamais aide personne a comprendre quoi que ce soit.
        raise HTTPException(500, f"sortie illisible de mastodonctl : {sortie[:200]}")


@app.get("/api/v1/mastodon/status")
async def status(_=Depends(_exige_jwt)):
    return _ctl("status")


@app.get("/api/v1/mastodon/healthz")
async def healthz():
    """Sonde de vie du DEMON, sans authentification et sans rien reveler.

    Elle ne dit pas si l'instance tourne : c'est le role de /status, qui exige
    un jeton. Une sonde bavarde renseignerait un visiteur sur ce que la board
    heberge.
    """
    return {"ok": True}


@app.post("/api/v1/mastodon/install")
async def install(_=Depends(_exige_jwt)):
    return _ctl("install", delai=30)


@app.post("/api/v1/mastodon/start")
async def start(_=Depends(_exige_jwt)):
    return _ctl("start", delai=60)


@app.post("/api/v1/mastodon/stop")
async def stop(_=Depends(_exige_jwt)):
    return _ctl("stop", delai=60)


@app.post("/api/v1/mastodon/invite")
async def invite(_=Depends(_exige_jwt)):
    return _ctl("invite", delai=30)

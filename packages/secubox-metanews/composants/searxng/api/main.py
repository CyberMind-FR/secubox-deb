# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: composant SearXNG de secubox-metanews (#3581) — API hôte.

Socket /run/secubox/searxng.sock, servie sous /api/v1/searxng/ par nginx (préfixe retiré). Service DÉDIÉ
(secubox-searxng.service, utilisateur secubox-searxng), jamais monté dans l'agrégateur : POST /reload passe par sudo.

  GET  /health       sonde publique
  GET  /status       require_lecture   état global (conteneur, service SearXNG, API), sondes bornées + cache court
  GET  /components   require_lecture   les trois couches, une par ligne
  GET  /engines      require_lecture   moteurs actifs (/config de SearXNG) et désactivés (TOML)
  GET  /rechercher   require_jwt       q (1-256 caractères), page ; au plus 20 résultats {titre, url, extrait, moteur}
  POST /reload       require_jwt       searxngctl reload (sudo -n + systemd-run, argv exact), délai explicite

Handlers synchrones (`def`) : sondes, HTTP vers le conteneur et sudo tournent dans le pool de FastAPI, jamais sur la boucle.
Aucun délai dépassé ne devient une 500 : 504 (recherche, reload), « unknown » (sondes)."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

_ICI = Path(__file__).resolve().parents[1]
if str(_ICI) not in sys.path:
    sys.path.insert(0, str(_ICI))

from fastapi import Depends, FastAPI, HTTPException, Query  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from sbx_searxng import VERSION  # noqa: E402
from sbx_searxng import config as C  # noqa: E402
from sbx_searxng import recherche as R  # noqa: E402
from sbx_searxng import sondes as S  # noqa: E402

log = logging.getLogger("secubox.searxng")

CONFIG = os.environ.get("SECUBOX_SEARXNG_CONFIG", str(C.CHEMIN_DEFAUT))
# CacheDirectory=secubox-searxng de l'unité (systemd pose CACHE_DIRECTORY) ; sans lui, cache en mémoire seulement.
_CACHE_DIR = os.environ.get("CACHE_DIRECTORY", "").split(":")[0]
ETAT = S.Cache(Path(_CACHE_DIR) / "etat.json" if _CACHE_DIR else None, ttl=10.0)
MOTEURS = S.Cache(Path(_CACHE_DIR) / "moteurs.json" if _CACHE_DIR else None, ttl=60.0)

# argv EXACT, identique à la ligne de sudoers.d/secubox-searxng (vérifié par les tests). systemd-run : le contrôleur root
# s'exécute dans le contexte de PID 1, hors du bac à sable (ProtectSystem=strict) de cette unité.
ARGV_RELOAD = ["sudo", "-n", "/usr/bin/systemd-run", "--wait", "--pipe", "--collect", "--quiet",
               "/usr/sbin/searxngctl", "reload", "--json", "--acteur-stdin"]
DELAI_RELOAD = 120
_ACTEUR = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")

app = FastAPI(title="SecuBox SearXNG", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)


def _config() -> dict | None:
    try:
        return C.charger(CONFIG)
    except C.ConfigInvalide as e:
        log.warning("configuration refusée : %s", e)
        return None


def _releve() -> Dict[str, Any]:
    cfg = _config()
    if cfg is None:
        return {"erreur_config": True}
    return {"cfg": cfg, "releve": S.releve(cfg, api="running")}


def _etat() -> Dict[str, Any]:
    return ETAT.obtenir(_releve)


def _sans_config() -> Dict[str, Any]:
    return {"module": "searxng", "version": VERSION, "overall": "red", "erreur": f"configuration refusée : {CONFIG}"}


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "module": "searxng"}


@app.get("/status", dependencies=[Depends(require_lecture)])
def status() -> Dict[str, Any]:
    e = _etat()
    if e.get("erreur_config"):
        return _sans_config()
    return S.vue_status(e["releve"])


@app.get("/components", dependencies=[Depends(require_lecture)])
def components() -> Dict[str, Any]:
    e = _etat()
    if e.get("erreur_config"):
        return {**_sans_config(), "components": []}
    return S.vue_components(e["releve"], e["cfg"])


@app.get("/engines", dependencies=[Depends(require_lecture)])
def engines() -> Dict[str, Any]:
    cfg = _config()
    if cfg is None:
        return {**_sans_config(), "actifs": None, "desactives": []}
    m = MOTEURS.obtenir(lambda: R.moteurs(cfg))
    return {"module": "searxng", **m, "sans_reponse_recente": R.sans_reponse_recente(),
            "note": "SearXNG ne publie pas ses suspensions (enable_metrics: false) : « sans réponse » vient de la dernière recherche."}


@app.get("/rechercher")
def rechercher(q: str = Query(..., min_length=1, max_length=256), page: int = Query(1, ge=1, le=50),
               _u: Dict[str, Any] = Depends(require_jwt)) -> Dict[str, Any]:
    q = q.strip()
    if not q or any(ord(c) < 32 or ord(c) == 127 for c in q):
        raise HTTPException(status_code=422, detail="q : texte de 1 à 256 caractères imprimables")
    cfg = _config()
    if cfg is None:
        raise HTTPException(status_code=503, detail="configuration SearXNG refusée")
    try:
        return R.rechercher(cfg, q, page)
    except R.ErreurRecherche as e:
        raise HTTPException(status_code=e.code, detail=e.message) from e


@app.post("/reload")
def reload(u: Dict[str, Any] = Depends(require_jwt)) -> Dict[str, Any]:
    acteur = str(u.get("sub") or "")
    acteur = acteur if _ACTEUR.match(acteur) else "?"
    log.info("reload demandé par %s", acteur)
    try:
        p = subprocess.run(ARGV_RELOAD, input=json.dumps({"acteur": acteur}), capture_output=True, text=True,
                           timeout=DELAI_RELOAD, check=True)
        code, sortie, erreur = 0, p.stdout, p.stderr
    except subprocess.CalledProcessError as e:
        code, sortie, erreur = e.returncode, e.stdout or "", e.stderr or ""
    except subprocess.TimeoutExpired as e:
        raise HTTPException(status_code=504, detail=f"searxngctl reload sans réponse en {DELAI_RELOAD} s") from e
    except OSError as e:
        raise HTTPException(status_code=503, detail=f"sudo indisponible : {e.__class__.__name__}") from e
    finally:
        ETAT.oublier()
        MOTEURS.oublier()
    try:
        resultat = json.loads(sortie.strip().splitlines()[-1]) if sortie.strip() else None
    except ValueError:
        resultat = None
    if code == 0 and isinstance(resultat, dict):
        return resultat
    detail = resultat if isinstance(resultat, dict) else {"issue": "echec", "detail": (erreur or sortie).strip()[-500:]}
    # 3 : refusé ou défait (ancien settings.yml rétabli) ; 4 : conteneur absent ou arrêté ; 5 : un autre reload en cours.
    raise HTTPException(status_code=409 if code in (3, 4, 5) else 502, detail=detail)

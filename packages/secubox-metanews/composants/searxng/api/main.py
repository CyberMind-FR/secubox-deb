# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: composant SearXNG de secubox-metanews (#3581) — API hôte.

Socket /run/secubox/searxng.sock, servie sous /api/v1/searxng/ par nginx (préfixe retiré). Service DÉDIÉ
(secubox-searxng.service, utilisateur secubox-searxng, NoNewPrivileges), jamais monté dans l'agrégateur. L'API ne lance
rien en root : POST /reload DÉPOSE une demande que secubox-searxng-reload.path fait traiter par le contrôleur root.

  GET  /health       sonde publique
  GET  /status       require_lecture   état global (conteneur, service SearXNG, API), sondes bornées + cache court
  GET  /components   require_lecture   les trois couches, une par ligne
  GET  /engines      require_lecture   moteurs actifs (/config de SearXNG) et désactivés (TOML)
  GET  /rechercher   require_jwt       q (1-256 caractères), page ; au plus 20 résultats {titre, url, extrait, moteur}
  POST /reload       require_jwt       demande déposée, résultat attendu DELAI_RELOAD s ; au-delà 202 (issue à l'audit)

Handlers synchrones (`def`) : sondes, HTTP vers le conteneur et l'attente du résultat tournent dans le pool de FastAPI,
jamais sur la boucle. Aucun délai dépassé ne devient une 500 : 504 (recherche), 202 (reload), « unknown » (sondes)."""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path
from typing import Any, Dict

_ICI = Path(__file__).resolve().parents[1]
if str(_ICI) not in sys.path:
    sys.path.insert(0, str(_ICI))

from fastapi import Depends, FastAPI, HTTPException, Query  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
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

# Patron « oneshot root déclenché par fichier » (secubox-ssh #3401, secubox-reparer #3628) : l'API dépose
# <id>.demande = {"acteur": "<sub>"} dans DEMANDES (root:secubox-searxng 1770) ; secubox-searxng-reload.path démarre
# secubox-searxng-reload.service (« searxngctl reload --demandes », root), qui pose <id>.json dans RESULTATS
# (root:secubox-searxng 0750 : l'API lit seulement, le contrôleur purge).
DEMANDES = Path(os.environ.get("SECUBOX_SEARXNG_DEMANDES", "/run/secubox/searxng-reload"))
RESULTATS = Path(os.environ.get("SECUBOX_SEARXNG_RESULTATS", "/run/secubox/searxng-reload-resultats"))
# Même délai d'attente que le patron (secubox-ssh, 30 s). Un reload ordinaire tient dedans (relance de SearXNG puis
# sonde /healthz, quelques secondes) ; le pire cas du contrôleur (sonde de santé 30 s, puis retour arrière avec une
# seconde relance et une seconde sonde) le dépasse : 202, et l'issue est au journal d'audit. Le contrôleur, lui, est
# borné par TimeoutStartSec de secubox-searxng-reload.service.
DELAI_RELOAD = 30.0
TAILLE_RESULTAT = 16 * 1024
_ACTEUR = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
_NOM_DEMANDE = re.compile(r"^[0-9a-f]{16}\.demande$")

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


def _demande_en_attente() -> bool:
    return any(_NOM_DEMANDE.fullmatch(n) for n in os.listdir(DEMANDES))


def _deposer(acteur: str) -> str:
    """<id>.demande créé à côté (.tmp.<id>, O_EXCL|O_NOFOLLOW : jamais à travers une entrée déjà posée), puis renommé dans
    le même dossier : le contrôleur ne voit jamais une demande à moitié écrite."""
    ident = secrets.token_hex(8)
    tmp = DEMANDES / f".tmp.{ident}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump({"acteur": acteur}, f)
        os.replace(tmp, DEMANDES / f"{ident}.demande")
    except OSError:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return ident


def _lire_resultat(ident: str) -> dict | None:
    """Le résultat posé par le contrôleur, ou None s'il n'est pas (encore) là. Lien refusé, taille bornée."""
    try:
        fd = os.open(RESULTATS / f"{ident}.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > TAILLE_RESULTAT:
            return {"code": 1, "resultat": {"issue": "echec", "detail": "résultat du contrôleur illisible"}}
        brut = os.read(fd, TAILLE_RESULTAT + 1)
    finally:
        os.close(fd)
    try:
        d = json.loads(brut.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None                      # remplacé atomiquement par le contrôleur : jamais partiel ; on relira
    return d if isinstance(d, dict) else {"code": 1, "resultat": {"issue": "echec", "detail": "résultat illisible"}}


_dormir = time.sleep


def _attendre_resultat(ident: str, delai: float, pause: float = 0.2) -> dict | None:
    fin = time.monotonic() + delai
    while True:
        try:
            r = _lire_resultat(ident)
        except OSError as e:
            log.warning("résultat %s illisible : %s", ident, e.__class__.__name__)
            r = None
        if r is not None:
            return r
        if time.monotonic() >= fin:
            return None
        _dormir(pause)


@app.post("/reload")
def reload(u: Dict[str, Any] = Depends(require_jwt)):
    acteur = str(u.get("sub") or "")
    acteur = acteur if _ACTEUR.fullmatch(acteur) else "?"
    log.info("reload demandé par %s", acteur)
    try:
        if _demande_en_attente():
            raise HTTPException(status_code=409, detail={"issue": "occupe", "detail": "un rechargement est déjà demandé"})
        ident = _deposer(acteur)
    except OSError as e:
        log.error("demande de rechargement non déposée : %s", e.__class__.__name__)
        raise HTTPException(status_code=503, detail={
            "issue": "echec", "detail": "demande non déposée : secubox-searxng-reload.path est-il installé et actif ?"}) from e
    try:
        res = _attendre_resultat(ident, DELAI_RELOAD)
    finally:
        ETAT.oublier()
        MOTEURS.oublier()
    if res is None:
        return JSONResponse(status_code=202, content={
            "issue": "en-cours", "demande": ident,
            "detail": f"rechargement toujours en cours après {int(DELAI_RELOAD)} s : son issue sera consignée au journal "
                      "d'audit (/var/log/secubox/audit.log)"})
    code, resultat = res.get("code"), res.get("resultat")
    if code == 0 and isinstance(resultat, dict):
        return resultat
    detail = resultat if isinstance(resultat, dict) else {"issue": "echec", "detail": "résultat du contrôleur illisible"}
    # 3 : refusé ou défait (ancien settings.yml rétabli) ; 4 : conteneur absent ou arrêté ; 5 : un autre reload en cours.
    raise HTTPException(status_code=409 if code in (3, 4, 5) else 502, detail=detail)

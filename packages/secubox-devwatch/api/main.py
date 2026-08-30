# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: DevWatch
CyberMind — https://cybermind.fr

Suivi de développement en temps réel d'un dépôt GitHub amont, vulgarisé : cadence,
flèches d'efficience, temps cumulé, derniers commits, dernière release, chantiers
résiduels — et une couche d'émancipation (coût, carbone, campagne de soutien).

Architecture (patron double-cache maison) : une tâche de fond interroge l'API
GitHub PUBLIQUE toutes les N minutes et dépose un résumé prêt-à-servir ; les
endpoints ne touchent JAMAIS le réseau — ils rendent le cache. Le navigateur ne
parle qu'à la box (même origine) ; GitHub ne sait rien de qui regarde.

Personnel mais MUTUALISABLE : tout est réglable par TOML + un petit panneau admin
(JWT) qui saisit les flux STATIQUES (dépenses, soutien, abonnements) que le dépôt
ne connaît pas.
"""
from __future__ import annotations

import asyncio
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .github import GitHub
from . import metrics
from . import modules

log = get_logger("devwatch")

CONFIG_FILE = Path("/etc/secubox/devwatch.toml")
STATE_DIR = Path("/var/lib/secubox/devwatch")
CACHE_FILE = STATE_DIR / "cache.json"      # dernier résumé calculé
FLOWS_FILE = STATE_DIR / "flows.json"      # flux statiques saisis (admin)
CONFIG_OVR = STATE_DIR / "config.json"     # surcharges d'estimation (admin)
# Le PAT GitHub est un SECRET : jamais dans config.json (qui exclut « token »),
# jamais renvoyé par l'API. Fichier dédié 0600 dans l'état RW du service — le
# durcissement systemd (ProtectSystem=strict) rend /etc/secubox/secrets non
# inscriptible par le service ; l'état /var/lib/secubox l'est. Non versionné.
TOKEN_FILE = STATE_DIR / "github-token"

DEFAULT_CONFIG = {
    "owner": "CyberMind-FR",
    "repo": "secubox-deb",
    "token": "",                 # vide = API publique (60/h) ; sinon /etc/secubox/secrets
    "refresh_minutes": 20,
    # Paramètres d'ESTIMATION (réglables — vulgarisation, jamais des faits).
    "min_par_commit": 22,
    "tarif_horaire": 65,
    "co2_kg_par_heure": 0.17,
    "km_par_kg_co2": 5.3,
}
DEFAULT_FLOWS = {
    "depenses_cumulees": 2200,   # € — ce que le projet a coûté à ce jour (saisi)
    "sponsor_recu": 0,           # € — soutien externe reçu (saisi)
    "abonnement_mensuel": 120,   # €/mois — coûts récurrents (abonnements, hébergement)
    "note": "",
}


def _load_toml() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    flows = dict(DEFAULT_FLOWS)
    try:
        if CONFIG_FILE.exists():
            t = tomllib.loads(CONFIG_FILE.read_text())
            for k in DEFAULT_CONFIG:
                if k in t:
                    cfg[k] = t[k]
            fin = t.get("financement", {})
            for k in DEFAULT_FLOWS:
                if k in fin:
                    flows[k] = fin[k]
    except Exception as e:  # défensif : un TOML cassé ne doit pas tuer le service
        log.error(f"config TOML illisible: {e}")
    return cfg, flows


def _load_json(path: Path, base: dict) -> dict:
    """Surcharges admin (JSON) au-dessus des valeurs TOML/défaut."""
    out = dict(base)
    try:
        if path.exists():
            j = json.loads(path.read_text())
            if isinstance(j, dict):
                for k in base:
                    if k in j:
                        out[k] = j[k]
    except Exception as e:
        log.error(f"{path.name} illisible: {e}")
    return out


def _save_json(path: Path, data: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.replace(path)  # échange atomique — jamais de fichier à moitié écrit


def _load_token() -> str:
    """Le secret l'emporte sur le TOML. Absent/illisible = API publique (60/h)."""
    try:
        if TOKEN_FILE.exists():
            return TOKEN_FILE.read_text().strip()
    except Exception as e:
        log.error(f"token illisible: {e}")
    return ""


def _write_token(tok: str) -> None:
    """Écrit (0600) ou retire le secret. Vide = retour à l'API publique."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tok = (tok or "").strip()
    if not tok:
        try:
            TOKEN_FILE.unlink(missing_ok=True)
        except Exception as e:
            log.error(f"suppression token: {e}")
        return
    tmp = TOKEN_FILE.with_suffix(".tmp")
    tmp.write_text(tok)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(TOKEN_FILE)
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


# État vivant.
_TOML_CFG, _TOML_FLOWS = _load_toml()
CFG = _load_json(CONFIG_OVR, _TOML_CFG)
_sec = _load_token()
if _sec:
    CFG["token"] = _sec          # le secret sur disque prime sur le TOML
FLOWS = _load_json(FLOWS_FILE, _TOML_FLOWS)
SUMMARY: dict[str, Any] = {}
MODULES: dict[str, Any] = {"total": 0, "modules": []}  # révisions locales des paquets


def _scan_modules() -> None:
    global MODULES
    try:
        MODULES = modules.scan(limit=24)
    except Exception as e:  # défensif : un échec de scan ne casse rien
        log.error(f"scan modules: {e}")


def _recompute_from_cache() -> None:
    """Recalcule le résumé à partir des DERNIERS faits GitHub connus.

    Sert quand l'admin change un flux ou un paramètre : on ne rappelle pas
    GitHub (inutile et coûteux en quota) — on ré-assemble depuis le cache brut.
    """
    global SUMMARY
    raw = SUMMARY.get("_raw") if SUMMARY else None
    if not raw:
        return
    s = metrics.compute(raw, CFG, FLOWS)
    s["_raw"] = raw
    SUMMARY = s
    try:
        _save_json(CACHE_FILE, SUMMARY)
    except Exception as e:
        log.error(f"cache non écrit: {e}")


async def _poll_once() -> None:
    global SUMMARY
    gh = GitHub(CFG["owner"], CFG["repo"], token=str(CFG.get("token") or ""))
    raw = await gh.collect()
    if not raw.get("ok"):
        log.warning(f"passe GitHub incomplète: {raw.get('error')} (quota {raw.get('rate_left')})")
        # On garde le dernier bon résumé ; on note juste l'échec s'il y en a un.
        if SUMMARY:
            SUMMARY.setdefault("meta", {})["error"] = raw.get("error")
            SUMMARY["meta"]["rate_left"] = raw.get("rate_left")
        return
    s = metrics.compute(raw, CFG, FLOWS)
    s["_raw"] = raw          # on garde les faits pour recalculer sans réseau
    SUMMARY = s
    try:
        _save_json(CACHE_FILE, SUMMARY)
    except Exception as e:
        log.error(f"cache non écrit: {e}")
    log.info(f"passe OK — {raw.get('commits_total')} commits, quota {raw.get('rate_left')}")


async def _fill_activity() -> None:
    """Comble la cadence quand GitHub calculait encore l'agrégat hebdo (202).

    Reprise ÉCONOME et BORNÉE : un seul appel toutes les 90 s, ~15 fois au plus
    (≈ 22 min — GitHub a fini bien avant), puis on laisse le cycle normal faire.
    Un seul appel/reprise préserve le quota anonyme.
    """
    global SUMMARY
    gh = GitHub(CFG["owner"], CFG["repo"], token=str(CFG.get("token") or ""))
    for _ in range(15):
        await asyncio.sleep(90)
        raw = SUMMARY.get("_raw") if SUMMARY else None
        if not raw or not raw.get("weeks_pending"):
            return  # une passe complète a déjà comblé la cadence entre-temps
        try:
            weeks = await gh.activity_only()
        except Exception as e:
            log.error(f"fill_activity: {e}")
            weeks = None
        if weeks:
            raw["weeks"] = weeks
            raw["weeks_pending"] = False
            _recompute_from_cache()
            log.info("cadence comblée (agrégat hebdo prêt)")
            return


async def _refresher() -> None:
    # Petite latence de démarrage : laisser le socket se poser avant le réseau.
    await asyncio.sleep(3)
    while True:
        _scan_modules()   # LOCAL (dpkg + changelogs) : indépendant du quota GitHub
        try:
            await _poll_once()
            raw = SUMMARY.get("_raw") if SUMMARY else None
            # Cadence encore en calcul côté GitHub : reprise économe en fond,
            # sans retenir le cycle principal.
            if raw and raw.get("weeks_pending"):
                asyncio.create_task(_fill_activity())
        except Exception as e:  # une passe ratée ne tue jamais la boucle
            log.error(f"refresher: {e}")
        await asyncio.sleep(max(300, int(CFG.get("refresh_minutes", 20)) * 60))


app = FastAPI(title="secubox-devwatch", version="1.0.0", root_path="/api/v1/devwatch")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()


@app.on_event("startup")
async def _startup() -> None:
    global SUMMARY
    # Service PRÊT tout de suite : on sert le dernier cache disque si présent.
    if CACHE_FILE.exists():
        try:
            SUMMARY = json.loads(CACHE_FILE.read_text())
        except Exception as e:
            log.error(f"cache initial illisible: {e}")
    _scan_modules()   # révisions locales dispo dès la première requête
    asyncio.create_task(_refresher())


@router.get("/health")
async def health() -> dict:
    m = SUMMARY.get("meta", {}) if SUMMARY else {}
    return {"ok": bool(SUMMARY.get("ok")) if SUMMARY else False,
            "fetched_at": m.get("fetched_at"), "rate_left": m.get("rate_left"),
            "repo": f"{CFG['owner']}/{CFG['repo']}"}


@router.get("/summary")
async def summary() -> JSONResponse:
    if not SUMMARY:
        return JSONResponse({"ok": False, "warming": True,
                             "repo": {"full": f"{CFG['owner']}/{CFG['repo']}"},
                             "modules": MODULES})
    # On ne renvoie pas `_raw` (volumineux, interne). On joint les révisions
    # LOCALES des modules (indépendantes du quota GitHub).
    out = {k: v for k, v in SUMMARY.items() if k != "_raw"}
    out["modules"] = MODULES
    return JSONResponse(out)


@router.get("/modules")
async def get_modules() -> JSONResponse:
    return JSONResponse(MODULES)


@router.get("/flows")
async def get_flows() -> dict:
    # Lecture publique : ces chiffres sont ceux qu'affiche le tableau de bord.
    return dict(FLOWS)


class Flows(BaseModel):
    depenses_cumulees: float | None = None
    sponsor_recu: float | None = None
    abonnement_mensuel: float | None = None
    note: str | None = None


@router.post("/flows", dependencies=[Depends(require_jwt)])
async def set_flows(body: Flows) -> dict:
    """Saisie admin des FLUX STATIQUES (webmin). Persistant, recalcul immédiat."""
    global FLOWS
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    FLOWS.update(upd)
    _save_json(FLOWS_FILE, FLOWS)
    _recompute_from_cache()
    log.info(f"flux mis à jour: {upd}")
    return {"ok": True, "flows": FLOWS}


class Params(BaseModel):
    owner: str | None = None
    repo: str | None = None
    refresh_minutes: int | None = None
    min_par_commit: float | None = None
    tarif_horaire: float | None = None
    co2_kg_par_heure: float | None = None
    km_par_kg_co2: float | None = None


@router.get("/config", dependencies=[Depends(require_jwt)])
async def get_config() -> dict:
    # Le token n'est JAMAIS renvoyé (secret) — on expose seulement s'il est présent.
    out = {k: v for k, v in CFG.items() if k != "token"}
    out["has_token"] = bool(CFG.get("token"))
    return out


class Token(BaseModel):
    token: str = ""      # PAT lecture seule ; vide = retour à l'API publique (60/h)


@router.post("/config/token", dependencies=[Depends(require_jwt)])
async def set_token(body: Token) -> dict:
    """Pose/retire le PAT GitHub (secret 0600). 60/h → 5000/h : la cadence se remplit.

    On l'applique à chaud puis on FORCE une passe : si le quota était la cause du
    « cadence à zéro », le bargraphe et today/last7 reviennent tout de suite.
    """
    tok = (body.token or "").strip()
    _write_token(tok)
    CFG["token"] = tok
    await _poll_once()
    ok = bool(SUMMARY.get("ok"))
    m = SUMMARY.get("meta", {}) if SUMMARY else {}
    return {"ok": ok, "has_token": bool(tok), "rate_left": m.get("rate_left"),
            "error": m.get("error"), "fetched_at": m.get("fetched_at")}


@router.post("/config", dependencies=[Depends(require_jwt)])
async def set_config(body: Params) -> dict:
    """Réglage admin des paramètres d'estimation / du dépôt suivi."""
    global CFG
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    CFG.update(upd)
    _save_json(CONFIG_OVR, {k: v for k, v in CFG.items() if k != "token"})
    _recompute_from_cache()   # les estimations bougent ; le dépôt sera repris à la prochaine passe
    log.info(f"paramètres mis à jour: {upd}")
    return {"ok": True, "config": {k: v for k, v in CFG.items() if k != "token"}}


@router.post("/refresh", dependencies=[Depends(require_jwt)])
async def refresh() -> dict:
    await _poll_once()
    return {"ok": bool(SUMMARY.get("ok")), "fetched_at": SUMMARY.get("meta", {}).get("fetched_at")}


app.include_router(router)

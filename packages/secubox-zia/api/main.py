# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: ZIA Hall
CyberMind — https://cybermind.fr

L'IA locale d'AletheiaVox/SBXOS : l'interface humaine du bus d'objets du Hall. Elle ne
possède pas les données — elle interprète et orchestre les objets déjà exposés par le
bus (qui reste la source de vérité et applique l'ACL). Toujours locale (niveau 1) ;
délègue au VHOST (niveau 2) ou au remote (niveau 3, optionnel) quand il faut.

POC / P1 : FastAPI sur socket Unix ; répondeur heuristique + outils du bus (lecture
d'abord). Le modèle GGUF (llama.cpp) se branche plus tard sans changer l'interface.
"""
from __future__ import annotations

import json
import time
import tomllib
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .bus import Bus
from .tools import Tools
from .remote import Remote
from . import runtime

log = get_logger("zia")

CONFIG_FILE = Path("/etc/secubox/zia.toml")
DEFAULT_CONFIG = {
    "model_name": "heuristique",     # affiché dans la carte ; « TinyLlama · Q4 » plus tard
    "llm_url": "",                   # llama-server (vide = répondeur heuristique)
    "n_predict": 120,
    "llm_timeout_s": 20,
    "metanews_sock": "/run/secubox/metanews.sock",
    "webos_sock": "/run/secubox/webos.sock",
    "billets_sock": "/run/secubox/billets.sock",
    "peertube_url": "https://peertube.gk2.secubox.in",
    "bus_cache_s": 45,
    "default_role": "guest",         # rôle du demandeur tant que l'auth n'est pas branchée
    # Niveau 3 (remote) — DÉSACTIVÉ par défaut ; soumis à politique + budget.
    "remote_enabled": False,
    "remote_role_min": "admin",
    "remote_url": "",                # endpoint distant (vide = jamais d'escalade)
    "remote_timeout_s": 15,
    "remote_budget": 20,             # nb max d'escalades / heure (garde-fou)
}


# État admin : surcouche de config saisie via la webui (JSON), qui l'emporte sur le
# TOML livré. Même esprit que DevWatch — modifiable sans toucher au fichier système.
STATE_DIR = Path("/var/lib/secubox/zia")
CONFIG_OVR = STATE_DIR / "config.json"


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG_FILE.exists():
            t = tomllib.loads(CONFIG_FILE.read_text())
            for k in DEFAULT_CONFIG:
                if k in t:
                    cfg[k] = t[k]
    except Exception as e:  # défensif : un TOML cassé ne doit pas tuer le service
        log.error(f"config illisible: {e}")
    # Surcouche admin (webui) par-dessus le TOML.
    try:
        if CONFIG_OVR.exists():
            ov = json.loads(CONFIG_OVR.read_text())
            for k in DEFAULT_CONFIG:
                if k in ov:
                    cfg[k] = ov[k]
    except Exception as e:
        log.error(f"surcouche config illisible: {e}")
    return cfg


def _save_overlay(cfg: dict) -> None:
    """Persiste la config admin (les clés connues), pour survie au redémarrage."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        data = {k: cfg[k] for k in DEFAULT_CONFIG if k in cfg}
        tmp = CONFIG_OVR.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        tmp.replace(CONFIG_OVR)
    except Exception as e:
        log.error(f"écriture surcouche config: {e}")


CFG = load_config()
BUS = Bus(CFG)
TOOLS = Tools(BUS)
REMOTE = Remote()
_M = {"chats": 0, "ms_total": 0.0, "started": time.time()}

# Journal d'audit minimal des actions (RFC §9.9) : qui/rôle, cible, action,
# valeur, résultat, horodatage — append-only JSONL, best-effort (jamais bloquant).
AUDIT_FILE = Path("/var/log/secubox/zia/actions.jsonl")


def _audit(role: str, actions: list) -> None:
    if not actions:
        return
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_FILE.open("a", encoding="utf-8") as fh:
            for a in actions:
                fh.write(json.dumps({
                    "ts": round(time.time(), 3), "role": role,
                    "target": a.get("target"), "service": a.get("service"),
                    "action": a.get("action"), "params": a.get("params"),
                    "result": "proposée",   # shadow : le Hall exécute, ZIA propose
                }, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error(f"audit action: {e}")

app = FastAPI(title="secubox-zia", version="0.1.0", root_path="/api/v1/zia")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()


class ChatIn(BaseModel):
    message: str
    role: Optional[str] = None      # guest|registered|member|admin (défaut config)


class Params(BaseModel):
    """Réglages admin de ZIA (tous facultatifs — on ne met à jour que ce qui vient)."""
    model_name: Optional[str] = None
    llm_url: Optional[str] = None
    n_predict: Optional[int] = None
    llm_timeout_s: Optional[float] = None
    default_role: Optional[str] = None
    bus_cache_s: Optional[float] = None
    peertube_url: Optional[str] = None
    metanews_sock: Optional[str] = None
    webos_sock: Optional[str] = None
    billets_sock: Optional[str] = None
    remote_enabled: Optional[bool] = None
    remote_role_min: Optional[str] = None
    remote_url: Optional[str] = None
    remote_timeout_s: Optional[float] = None
    remote_budget: Optional[int] = None


def _apply_config(upd: dict) -> None:
    """Applique une mise à jour EN PLACE : CFG est partagé par le bus/outils/runtime.

    On mute le dict global (le bus tient la même référence) et on rafraîchit les
    quelques valeurs dérivées à l'init (TTL du cache). llm_url, rôles, endpoints et
    politique remote sont relus à chaud à chaque requête — rien d'autre à recharger.
    """
    CFG.update(upd)
    try:
        BUS.ttl = float(CFG.get("bus_cache_s", 45))
        BUS._ts = 0.0                      # invalide le cache : la prochaine vue relit les adapters
    except Exception:
        pass


@router.get("/health")
async def health() -> dict:
    return {"ok": True, "engine": "llm" if CFG.get("llm_url") else "heuristique",
            "model": CFG.get("model_name"), "uptime_s": round(time.time() - _M["started"])}


@router.get("/metrics")
async def metrics() -> dict:
    n = _M["chats"] or 1
    objs = await BUS.objets(role="admin")   # compte total (vue admin), pour info
    return {"chats": _M["chats"], "latence_ms_moy": round(_M["ms_total"] / n, 1),
            "objets_bus": len(objs), "engine": "llm" if CFG.get("llm_url") else "heuristique",
            "model": CFG.get("model_name"), "tools": [t["name"] for t in TOOLS.schemas()],
            "remote_enabled": bool(CFG.get("remote_enabled"))}


@router.post("/v1/chat")
async def chat(body: ChatIn) -> JSONResponse:
    """Un message → texte + objets référencés (du bus, filtrés ACL) + trace + délégation.

    Le rôle borne ce qui est visible : le LLM ne voit jamais ce que le demandeur n'a pas
    le droit de voir. Les objets viennent des OUTILS, jamais de la génération.
    """
    role = (body.role or CFG.get("default_role") or "guest").strip().lower()
    t0 = time.time()
    try:
        out = await runtime.respond(body.message, role, TOOLS, CFG, REMOTE)
    except Exception as e:  # jamais d'exception nue vers le client
        log.error(f"chat: {e}")
        out = {"text": "Désolé, j'ai buté sur cette demande. Réessaie autrement ?",
               "objects": [], "trace": [], "delegate": None, "engine": "heuristique"}
    # `actions[]` fait TOUJOURS partie du contrat de réponse (RFC §7) — vide par
    # défaut. Ce sont des actions SBX déjà VALIDÉES (cible/action/rôle/valeur) que
    # la cardlet ZIA transmet au Hall ; ZIA ne touche jamais le DOM.
    out.setdefault("actions", [])
    _audit(role, out.get("actions") or [])
    dt = (time.time() - t0) * 1000
    _M["chats"] += 1
    _M["ms_total"] += dt
    out["meta"] = {"role": role, "ms": round(dt, 1)}
    return JSONResponse(out)


@router.get("/capabilities")
async def capabilities() -> dict:
    """Registre PUBLIC des capacités (bootstrap + manifestes) — lu par le Hall pour
    résoudre une action sémantique en message `sbx` natif (client SBXCapabilities).
    Lecture seule, pas de secret : la même liste blanche que le serveur applique."""
    return {"capabilities": BUS.caps.registry()}


@router.get("/config", dependencies=[Depends(require_jwt)])
async def get_config() -> dict:
    """Config courante (TOML + surcouche admin). Pas de secret dans ZIA au P1."""
    return {k: CFG.get(k) for k in DEFAULT_CONFIG}


@router.post("/config", dependencies=[Depends(require_jwt)])
async def set_config(body: Params) -> dict:
    """Réglage admin de ZIA — appliqué à chaud et persisté (surcouche JSON)."""
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    # Garde-fous simples : rôles connus, nombres positifs.
    roles = {"guest", "registered", "member", "admin"}
    if "default_role" in upd and upd["default_role"] not in roles:
        upd.pop("default_role")
    if "remote_role_min" in upd and upd["remote_role_min"] not in roles:
        upd.pop("remote_role_min")
    _apply_config(upd)
    _save_overlay(CFG)
    log.info(f"config ZIA mise à jour: {list(upd)}")
    return {"ok": True, "engine": "llm" if CFG.get("llm_url") else "heuristique",
            "config": {k: CFG.get(k) for k in DEFAULT_CONFIG}}


@router.post("/llm/test", dependencies=[Depends(require_jwt)])
async def llm_test() -> dict:
    """Ping du llama-server configuré (health + modèle) — pour valider llm_url."""
    url = str(CFG.get("llm_url", "") or "").strip()
    if not url:
        return {"ok": False, "reason": "llm_url vide — moteur heuristique"}
    try:
        async with httpx.AsyncClient(timeout=6.0) as cli:
            r = await cli.get(url.rstrip("/") + "/health")
            h = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            # /props expose le modèle chargé (llama.cpp) — best-effort.
            model = None
            try:
                p = await cli.get(url.rstrip("/") + "/props")
                if p.status_code == 200:
                    model = (p.json() or {}).get("default_generation_settings", {}).get("model") \
                        or (p.json() or {}).get("model_path")
            except Exception:
                pass
            ok = r.status_code == 200 and (h.get("status") in (None, "ok") or True)
            return {"ok": ok, "status": h.get("status", r.status_code), "model": model, "url": url}
    except Exception as e:
        return {"ok": False, "reason": f"injoignable : {e.__class__.__name__}", "url": url}


# Outils protégés à venir (écriture) : dependencies=[Depends(require_jwt)].
app.include_router(router)

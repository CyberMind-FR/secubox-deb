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

import time
import tomllib
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
    "bus_cache_s": 45,
    "default_role": "guest",         # rôle du demandeur tant que l'auth n'est pas branchée
    # Niveau 3 (remote) — DÉSACTIVÉ par défaut ; soumis à politique + budget.
    "remote_enabled": False,
    "remote_role_min": "admin",
    "remote_url": "",                # endpoint distant (vide = jamais d'escalade)
    "remote_timeout_s": 15,
    "remote_budget": 20,             # nb max d'escalades / heure (garde-fou)
}


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
    return cfg


CFG = load_config()
BUS = Bus(CFG)
TOOLS = Tools(BUS)
REMOTE = Remote()
_M = {"chats": 0, "ms_total": 0.0, "started": time.time()}

app = FastAPI(title="secubox-zia", version="0.1.0", root_path="/api/v1/zia")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()


class ChatIn(BaseModel):
    message: str
    role: Optional[str] = None      # guest|registered|member|admin (défaut config)


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
    dt = (time.time() - t0) * 1000
    _M["chats"] += 1
    _M["ms_total"] += dt
    out["meta"] = {"role": role, "ms": round(dt, 1)}
    return JSONResponse(out)


# Outils protégés à venir (écriture) : dependencies=[Depends(require_jwt)].
app.include_router(router)

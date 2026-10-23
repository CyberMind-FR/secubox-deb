# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: composant turn (secubox-jitsi)
CyberMind — https://cybermind.fr

TURN/STUN (coturn) : état, relais, identifiants temporaires, utilisateurs.

L'API tourne sous `secubox` et NE PILOTE RIEN elle-même (#3060) : chaque acte
privilégié — lire la configuration de coturn (root:turnserver), le démarrer,
le relancer, régénérer sa configuration, gérer les utilisateurs de sa base —
passe par `sudo -n /usr/sbin/secubox-turnctl <verbe exact>` (sudoers/secubox-turn).
Le ctl répond en JSON ; l'API le relaie et valide les entrées AVANT de l'appeler.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import require_jwt
from secubox_core.auth import router as auth_router
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-turn", version="2.0.0", root_path="/api/v1/turn")


@app.get("/health")
async def health_root():
    """Health check (public) pour la barre latérale."""
    return {"status": "ok", "module": "turn"}


app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("turn")

CTL = "/usr/sbin/secubox-turnctl"
JOURNAL = Path("/var/log/turnserver/turnserver.log")
NOM = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOTE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")


def _ctl(*args: str, stdin: Optional[str] = None, timeout: int = 30) -> dict:
    """`sudo -n secubox-turnctl <verbe> [args]` → dict. Jamais d'exception : un échec est un dict {success: False, error}."""
    try:
        r = subprocess.run(["sudo", "-n", CTL, *args], input=stdin, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "le ctl ne répond pas"}
    except OSError as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}
    sortie = (r.stdout or "").strip()
    try:
        data = json.loads(sortie) if sortie else {}
    except ValueError:
        data = {}
    if r.returncode != 0:
        return {"success": False, "error": data.get("error") or (r.stderr or "").strip()[-300:] or f"ctl rc={r.returncode}"}
    return data


def _etat() -> dict:
    return _ctl("status")


def _urls(etat: dict) -> dict:
    realm = etat.get("realm") or "localhost"
    port = etat.get("listening_port") or 3478
    tls = etat.get("tls_port")
    turn = [f"turn:{realm}:{port}", f"turn:{realm}:{port}?transport=tcp"]
    if tls:
        turn.append(f"turns:{realm}:{tls}")
    return {"turn_urls": turn, "stun_urls": [f"stun:{realm}:{port}"]}


# ── État ───────────────────────────────────────────────────────────────────────

@router.get("/health")
async def health():
    return {"status": "ok", "module": "turn", "version": "2.0.0"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    e = _etat()
    if e.get("success") is False:
        return {"service": None, "error": e.get("error")}
    return {
        "service": {"active": e.get("active"), "enabled": e.get("enabled"), "pid": e.get("pid"),
                    "uptime_seconds": e.get("uptime_seconds")},
        "realm": e.get("realm", ""),
        "listening_port": e.get("listening_port"),
        "tls_port": e.get("tls_port"),
        "min_port": e.get("min_port"),
        "max_port": e.get("max_port"),
        "config_exists": True,
        "config_secubox": bool(e.get("config_secubox")),
        "secret_configured": bool(e.get("secret_configured")),
        "users_count": e.get("users_count", 0),
        "listening_ips": e.get("listening_ips", []),
    }


def _journal(n: int) -> list[str]:
    if JOURNAL.exists():
        try:
            return JOURNAL.read_text(errors="replace").splitlines()[-n:]
        except OSError:
            pass
    return list((_ctl("journal", str(n)) or {}).get("lines") or [])


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    sessions = (_ctl("sessions") or {}).get("sessions") or []
    lignes = _journal(1000)
    total = sum(1 for ligne in lignes if "allocation created" in ligne.lower())
    refus = sum(1 for ligne in lignes if "authentication failed" in ligne.lower() or "401" in ligne)
    return {
        "active_sessions": len(sessions),
        "udp_connections": sum(1 for s in sessions if str(s.get("protocol", "")).startswith("udp")),
        "tcp_connections": sum(1 for s in sessions if str(s.get("protocol", "")).startswith("tcp")),
        "total_allocations": total,
        "auth_failures": refus,
        "total_data_relayed_bytes": 0,
    }


@router.get("/sessions")
async def sessions(user=Depends(require_jwt)):
    brut = (_ctl("sessions") or {}).get("sessions") or []
    out = []
    for s in brut:
        remote = str(s.get("remote_addr", ""))
        ip, _, port = remote.rpartition(":") if ":" in remote else (remote, "", "")
        out.append({"client_ip": ip, "client_port": port, "protocol": s.get("protocol", ""),
                    "local_addr": s.get("local_addr", ""), "state": s.get("state", "")})
    return {"sessions": out, "count": len(out)}


# ── Service ────────────────────────────────────────────────────────────────────

@router.post("/start")
async def start(user=Depends(require_jwt)):
    r = _ctl("start")
    log.info("TURN start: %s", r.get("success"))
    return r


@router.post("/stop")
async def stop(user=Depends(require_jwt)):
    r = _ctl("stop")
    log.info("TURN stop: %s", r.get("success"))
    return r


@router.post("/restart")
async def restart(user=Depends(require_jwt)):
    r = _ctl("restart")
    log.info("TURN restart: %s", r.get("success"))
    return r


@router.post("/generer")
async def generer(user=Depends(require_jwt)):
    """Réparer : configuration SecuBox de coturn régénérée (double tampon, retour arrière si coturn ne repart pas)."""
    r = _ctl("generer", timeout=60)
    log.info("TURN generer: %s", r.get("success"))
    return r


# ── Configuration (générée, lecture seule) ─────────────────────────────────────

@router.get("/config")
async def get_config(user=Depends(require_jwt)):
    r = _ctl("config")
    if r.get("success") is False:
        return {"content": "", "parsed": {}, "error": r.get("error")}
    return {"content": r.get("content", ""), "parsed": _etat(), "generee": True}


class ConfigRequest(BaseModel):
    content: str


@router.post("/config")
async def set_config(req: ConfigRequest, user=Depends(require_jwt)):
    raise HTTPException(status_code=409, detail="configuration générée par SecuBox : changer le domaine par /realm, "
                                                "régénérer par /generer ; pas d'édition à la main")


# ── Utilisateurs (base de coturn) ──────────────────────────────────────────────

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    r = _ctl("users")
    return {"users": r.get("users") or [], **({"error": r["error"]} if r.get("success") is False else {})}


class UserRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


@router.post("/users")
async def add_user(req: UserRequest, user=Depends(require_jwt)):
    if not NOM.match(req.username):
        return {"success": False, "error": "nom : lettres, chiffres, . _ - (64 max)"}
    if "\n" in req.password:
        return {"success": False, "error": "mot de passe invalide"}
    r = _ctl("user-add", req.username, stdin=req.password + "\n")
    log.info("TURN user-add %s: %s", req.username, r.get("success"))
    return r


@router.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_jwt)):
    if not NOM.match(username):
        return {"success": False, "error": "nom invalide"}
    r = _ctl("user-del", username)
    log.info("TURN user-del %s: %s", username, r.get("success"))
    return r


# ── Domaine et secret ──────────────────────────────────────────────────────────

@router.get("/realm")
async def get_realm_endpoint(user=Depends(require_jwt)):
    e = _etat()
    return {"realm": e.get("realm", ""), "secret_configured": bool(e.get("secret_configured"))}


class RealmRequest(BaseModel):
    realm: str = Field(min_length=1, max_length=253)
    secret: Optional[str] = None  # ignoré : le secret est généré côté serveur (voir /generate_secret)


@router.post("/realm")
async def set_realm(req: RealmRequest, user=Depends(require_jwt)):
    realm = req.realm.strip().lower()
    if not HOTE.match(realm):
        return {"success": False, "error": "domaine invalide"}
    r = _ctl("generer", realm, timeout=60)
    log.info("TURN realm %s: %s", realm, r.get("success"))
    if r.get("success"):
        r["message"] = "Domaine appliqué : configuration régénérée et coturn relancé."
    return r


@router.post("/generate_secret")
async def generate_secret(user=Depends(require_jwt)):
    """Renouvelle le secret partagé côté serveur et régénère : il n'est jamais renvoyé au navigateur."""
    r = _ctl("secret-renouveler", timeout=60)
    log.info("TURN secret renouvelé: %s", r.get("success"))
    if r.get("success"):
        r["message"] = "Secret renouvelé et appliqué ; les identifiants temporaires déjà émis cessent de valoir."
    return r


# ── Identifiants temporaires (TURN REST API) ───────────────────────────────────

class CredentialRequest(BaseModel):
    username: str = "webrtc"
    ttl: int = Field(default=86400, ge=60, le=604800)


def _credentials(username: str, ttl: int) -> dict:
    if not NOM.match(username):
        return {"error": "nom invalide"}
    return _ctl("credentials", username, str(ttl))


@router.get("/credentials")
async def get_credentials(user=Depends(require_jwt)):
    return _credentials("test-user", 3600)


@router.post("/credentials")
async def generate_credentials(req: CredentialRequest, user=Depends(require_jwt)):
    return _credentials(req.username, req.ttl)


# ── Journaux et topologie ──────────────────────────────────────────────────────

@router.get("/logs")
def get_logs(lines: int = 100, user=Depends(require_jwt)):
    n = max(1, min(int(lines), 2000))
    return {"lines": _journal(n)}


@router.get("/components")
async def components(user=Depends(require_jwt)):
    e = _etat()
    return {"components": [
        {"name": "coturn", "type": "service", "description": "TURN/STUN server daemon", "status": bool(e.get("active"))},
        {"name": "secubox-turnctl", "type": "cli", "description": "actionneur root (verbes exacts, sudoers)", "available": Path(CTL).exists()},
        {"name": "turnserver.conf", "type": "config", "description": "configuration générée par SecuBox",
         "exists": True, "secubox": bool(e.get("config_secubox"))},
    ]}


@router.get("/access")
async def access(user=Depends(require_jwt)):
    e = _etat()
    realm = e.get("realm") or "localhost"
    port = e.get("listening_port") or 3478
    tls = e.get("tls_port")
    eps = [
        {"name": "STUN UDP", "protocol": "stun", "host": realm, "port": port, "url": f"stun:{realm}:{port}"},
        {"name": "TURN UDP", "protocol": "turn", "host": realm, "port": port, "url": f"turn:{realm}:{port}"},
        {"name": "TURN TCP", "protocol": "turn", "host": realm, "port": port, "url": f"turn:{realm}:{port}?transport=tcp"},
    ]
    if tls:
        eps.append({"name": "TURNS TLS", "protocol": "turns", "host": realm, "port": tls, "url": f"turns:{realm}:{tls}"})
    return {"endpoints": eps, **_urls(e)}


app.include_router(router)

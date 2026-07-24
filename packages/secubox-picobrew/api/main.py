# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: PicoBrew — API de gestion.
CyberMind — https://cybermind.fr

Cette API ne fait AUCUNE action privilégiée : elle délègue à picobrewctl via
sudo. C'est la règle du dépôt — une seule surface root, auditée.
"""
import json
import subprocess
from fastapi import APIRouter, FastAPI

CTL = "/usr/sbin/picobrewctl"

app = FastAPI(title="SecuBox PicoBrew")
router = APIRouter()


def _ctl(args: list[str], timeout: int = 20) -> tuple[int, str]:
    """Exécute picobrewctl via sudo. Renvoie (code, stdout).

    Ne lève jamais : un ctl absent, lent ou en erreur doit dégrader le panel,
    pas le faire tomber.
    """
    try:
        p = subprocess.run(["sudo", "-n", CTL, *args],
                           capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


@router.get("/status")
def status() -> dict:
    rc, out = _ctl(["status", "--json"])
    if rc != 0 or not out:
        return {"installed": False, "running": False, "ip": "", "pinned_sha": "none",
                "session_active": False, "error": "picobrewctl indisponible"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"installed": False, "running": False, "ip": "", "pinned_sha": "none",
                "session_active": False, "error": "réponse ctl illisible"}


@router.post("/start")
def start() -> dict:
    rc, _ = _ctl(["start"])
    return {"ok": rc == 0}


@router.post("/stop")
def stop() -> dict:
    rc, _ = _ctl(["stop"])
    return {"ok": rc == 0}


@router.post("/restart")
def restart() -> dict:
    # restart peut prendre quelques secondes (stop + start du conteneur).
    rc, _ = _ctl(["restart"], timeout=60)
    return {"ok": rc == 0}


@router.get("/logs")
def logs() -> dict:
    # Journal du service picobrew DANS le conteneur (best-effort ; conteneur à
    # l'arrêt → le ctl renvoie rc!=0, on rend une liste vide plutôt qu'une 500).
    rc, out = _ctl(["logs"], timeout=30)
    if rc != 0:
        return {"lines": [], "error": "conteneur à l'arrêt ou logs indisponibles"}
    return {"lines": out.splitlines()[-200:]}


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


app.include_router(router)

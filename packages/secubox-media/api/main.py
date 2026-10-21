# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-media — supports externes (plan de contrôle)
CyberMind — https://cybermind.fr

FastAPI sur /run/secubox/media.sock, proxifié par nginx sur /api/v1/media/.

CETTE API NE TOUCHE RIEN ELLE-MÊME. Elle tourne en `secubox` et délègue chaque
opération — monter, lister, copier — à `sudo -n /usr/sbin/mediactl`, la seule
surface privilégiée du module (webui -> ctl confiné). Le confinement des
chemins, la lecture seule et le refus de supprimer vivent dans le ctl, pas ici :
une garde posée dans la couche HTTP serait contournable par tout autre appelant.

Les VERBES D'ACTION exigent un jeton. La détection et la navigation n'en
demandent pas — elles ne modifient rien, et le panneau doit pouvoir s'afficher
avant toute authentification. Monter, démonter et transférer, si.

Partages SMB (#3000) : même règle avec `sudo -n /usr/sbin/smbctl`. Tout `/smb/*`
exige un jeton, lecture comprise : la liste des partages, des comptes et des
chemins servis est une information d'administration, pas une mesure publique.
Le mot de passe d'un compte SMB est transmis au ctl SUR L'ENTRÉE STANDARD,
jamais en argument (table des processus), et n'est jamais journalisé.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.auth import require_lecture

VERSION = "1.9.0"
CTL = "/usr/sbin/mediactl"
CTL_SMB = "/usr/sbin/smbctl"

log = logging.getLogger("secubox-media")

app = FastAPI(
    title="SecuBox Media",
    version=VERSION,
    root_path="/api/v1/media",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


async def _run_ctl(ctl: str, args: tuple, timeout: int, stdin: Optional[str] = None) -> Dict[str, Any]:
    """`sudo -n <ctl> <args>` hors boucle d'événements.

    Les arguments sont passés en LISTE, jamais concaténés dans un shell : ils
    contiennent des chemins choisis par l'utilisateur, et une interpolation
    ferait d'un nom de fichier une injection de commande. `stdin` porte un
    secret (mot de passe SMB) : jamais dans `args`, jamais dans un journal."""
    nom = ctl.rsplit("/", 1)[-1]

    def _run() -> Dict[str, Any]:
        try:
            p = subprocess.run(["sudo", "-n", ctl, *args], input=stdin,
                               capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise HTTPException(status_code=500, detail=f"{nom} introuvable ({ctl})")
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504,
                                detail=f"{nom} {args[0]} a dépassé {timeout}s")
        out = (p.stdout or "").strip()
        if not out:
            raise HTTPException(status_code=500,
                                detail=(p.stderr or f"{nom} n'a rien renvoyé")[:300])
        try:
            return json.loads(out.splitlines()[-1])
        except json.JSONDecodeError:
            raise HTTPException(status_code=500,
                                detail=f"sortie non JSON : {out[:200]!r}")

    return await asyncio.to_thread(_run)


async def _ctl(*args: str, timeout: int = 60) -> Dict[str, Any]:
    return await _run_ctl(CTL, args, timeout)


async def _smb(*args: str, timeout: int = 30, stdin: Optional[str] = None) -> Dict[str, Any]:
    """Un refus du ctl (`ok:false`) devient un 400 porteur du motif : le panneau l'affiche tel quel."""
    d = await _run_ctl(CTL_SMB, args, timeout, stdin)
    if d.get("ok") is False:
        raise HTTPException(status_code=400, detail=str(d.get("error") or "refusé par smbctl")[:300])
    return d


class PathBody(BaseModel):
    path: str


class MountBody(BaseModel):
    path: str
    # Ecriture = choix explicite. Le defaut protege un support fraichement
    # branche d'une modification non demandee ; l'opt-in sert a exporter.
    rw: bool = False


class TransferBody(BaseModel):
    src: str
    dst: str


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "media"}


@app.get("/detect", dependencies=[Depends(require_lecture)])
async def detect() -> Dict[str, Any]:
    """Supports détectés + alertes de stabilité du bus.

    Les alertes viennent en premier dans le panneau : proposer de parcourir un
    support dont le port déconnecte en boucle, sans le dire, est un mensonge."""
    return await _ctl("detect", timeout=30)


@app.get("/browse", dependencies=[Depends(require_lecture)])
async def browse(path: str = "") -> Dict[str, Any]:
    return await _ctl("browse", path, timeout=45)


@app.get("/roots", dependencies=[Depends(require_lecture)])
async def roots() -> Dict[str, Any]:
    """Racines déclarées : médiathèques des services et destinations.

    Le panneau ne devine aucun chemin — il affiche ce que le ctl déclare, donc
    exactement ce que le confinement autorise."""
    return await _ctl("roots", timeout=30)


@app.post("/mount")
async def mount(body: MountBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Monte un périphérique. Lecture seule sauf `rw` explicite."""
    args = ["mount", body.path] + (["--rw"] if body.rw else [])
    return await _ctl(*args, timeout=60)


class AutomountBody(BaseModel):
    path: str
    on: bool
    # Le mode du montage de démarrage : lecture seule sauf choix explicite.
    rw: bool = False


@app.post("/automount")
async def automount(body: AutomountBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Monter (ou non) ce support au démarrage (#1571). Mémorisé par UUID dans
    le ctl, qui refuse une partition système comme pour un montage."""
    args = ["automount-set", body.path, "on" if body.on else "off"] + (["--rw"] if body.rw and body.on else [])
    return await _ctl(*args, timeout=30)


@app.post("/unmount")
async def unmount(body: PathBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await _ctl("unmount", body.path, timeout=60)


@app.post("/copy")
async def copy(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Met une copie en file. Ne transfère pas ici : le drainage s'en charge."""
    return await _ctl("copy", body.src, body.dst, timeout=30)


@app.post("/sync")
async def sync(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Aligne la destination sur la source. Ne supprime jamais à destination."""
    return await _ctl("sync", body.src, body.dst, timeout=30)


@app.post("/compare")
async def compare(body: TransferBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Liste les écarts sans rien écrire."""
    return await _ctl("compare", body.src, body.dst, timeout=120)


@app.get("/jobs", dependencies=[Depends(require_lecture)])
async def jobs() -> Dict[str, Any]:
    return await _ctl("jobs", timeout=30)


# ════════════════════════════════════════════════════════════════════════════
# Partages SMB — ksmbd, par smbctl (#3000). Tout exige un jeton d'administrateur.
# ════════════════════════════════════════════════════════════════════════════
class SmbUserBody(BaseModel):
    user: str = Field(min_length=1, max_length=47)
    password: str = Field(min_length=1, max_length=128)


class SmbUserNameBody(BaseModel):
    user: str = Field(min_length=1, max_length=47)


class SmbShareBody(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    path: str = Field(min_length=1, max_length=512)
    readonly: bool = True
    users: List[str] = []
    comment: str = Field(default="", max_length=80)


class SmbShareNameBody(BaseModel):
    name: str = Field(min_length=1, max_length=40)


@app.get("/smb/status", dependencies=[Depends(require_jwt)])
async def smb_status() -> Dict[str, Any]:
    """Module noyau, service, écoute 445, comptes, partages (manuels et générés), racines partageables."""
    return await _smb("status")


@app.get("/smb/users", dependencies=[Depends(require_jwt)])
async def smb_users() -> Dict[str, Any]:
    return await _smb("users")


@app.post("/smb/users")
async def smb_user_add(body: SmbUserBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Crée ou modifie un compte SMB. Le mot de passe part sur l'entrée standard du ctl."""
    if "\n" in body.password or "\r" in body.password:
        raise HTTPException(status_code=400, detail="mot de passe sur une seule ligne")
    return await _smb("user-add", body.user, stdin=body.password + "\n")


@app.post("/smb/users/delete")
async def smb_user_del(body: SmbUserNameBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await _smb("user-del", body.user)


@app.post("/smb/shares")
async def smb_share_add(body: SmbShareBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Partage manuel d'un répertoire : le ctl refuse un chemin hors des racines déclarées
    (liens résolus), un nom réservé ou un partage généré par sync-shares."""
    args = ["share-add", body.name, body.path, "--ro" if body.readonly else "--rw"]
    users = [u.strip() for u in body.users if u and u.strip()]
    if users:
        args += ["--users", ",".join(users)]
    if body.comment.strip():
        args += ["--comment", body.comment.strip()]
    return await _smb(*args)


@app.post("/smb/shares/delete")
async def smb_share_del(body: SmbShareNameBody, _: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await _smb("share-del", body.name)


@app.post("/smb/sync-shares")
async def smb_sync_shares(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    """Un partage par support réellement monté (ksmbd ne traverse pas les points de montage)."""
    return await _smb("sync-shares")


@app.post("/smb/reload")
async def smb_reload(_: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return await _smb("reload", timeout=45)

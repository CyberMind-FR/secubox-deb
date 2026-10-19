# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: secubox-pseudo-routeur — API locale (socket /run/secubox/pseudo-routeur.sock), #2940.

gk2 peut devenir la passerelle DHCP du LAN plat de la Freebox, filet de secours (sonde,
#2940 Tache 1) arme en premier. Cette API ne fait AUCUN travail privilegie elle-meme :
chaque action est deleguee a `pseudo-routeurctl` (root, confine, audite) par sudo -n, meme
motif que secubox-jellyfin (voir MODULE-COMPLIANCE.md § WebUI-delegates-to-confined-ctl).

  GET  /etat          mode (gk2|freebox), sonde active                    (lecture)
  POST /activer       devient la passerelle (refuse si la sonde n'est pas active) (admin)
  POST /retour-freebox  revient a la Freebox, inconditionnel, chemin de secours    (admin)
  GET  /suggestions   appareils vus par la Freebox non classes par le NAC  (admin)
  GET  /journal       dernieres bascules de passerelle DHCP (audit.log)    (lecture)
  GET  /health        vivacite (publique)
"""
from __future__ import annotations

import json
import os
import subprocess

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from secubox_core.auth import require_jwt, require_lecture

CTL = os.environ.get("SECUBOX_PR_CTL", "/usr/sbin/pseudo-routeurctl")
AUDIT_LOG = os.environ.get("SECUBOX_PR_AUDIT_LOG", "/var/log/secubox/audit.log")
NAC_SOCK = os.environ.get("SECUBOX_PR_NAC_SOCK", "/run/secubox/nac.sock")
FREEBOX_SOCK = os.environ.get("SECUBOX_PR_FREEBOX_SOCK", "/run/secubox/freebox.sock")

app = FastAPI(title="SecuBox Pseudo-routeur", version="0.1.0")


def _run_ctl(*args: str, timeout: int = 30):
    """`sudo -n pseudo-routeurctl <args>` → (returncode, stdout, stderr). Ne leve jamais :
    un ctl absent/lent/en erreur doit degrader le panneau, pas planter la requete."""
    try:
        p = subprocess.run(["sudo", "-n", CTL, *args], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"pseudo-routeurctl {' '.join(args)} a expire apres {timeout}s"
    except OSError as e:
        return 1, "", f"appel a pseudo-routeurctl impossible : {e}"


def _ctl_json(*args: str, timeout: int = 30):
    rc, out, err = _run_ctl(*args, timeout=timeout)
    if rc == 2:
        return None, (err or out or "refuse").strip()[:500], 409
    if rc != 0:
        return None, (err or out or f"pseudo-routeurctl a quitte en erreur ({rc})").strip()[:500], 502
    try:
        return json.loads(out.strip() or "{}"), None, 200
    except json.JSONDecodeError:
        return None, f"pseudo-routeurctl a rendu une reponse illisible : {out[:300]!r}", 502


def _repondre(*args, timeout=30):
    data, erreur, code = _ctl_json(*args, timeout=timeout)
    if erreur is not None:
        return JSONResponse({"erreur": erreur}, status_code=code)
    return data


@app.get("/health")
async def health():
    return {"status": "ok", "module": "pseudo-routeur"}


@app.get("/etat", dependencies=[Depends(require_lecture)])
def etat():
    return _repondre("etat")


@app.post("/activer", dependencies=[Depends(require_jwt)])
def activer():
    return _repondre("activer")


@app.post("/retour-freebox", dependencies=[Depends(require_jwt)])
def retour_freebox():
    return _repondre("retour-freebox")


def _appel_uds(socket_path, chemin, entetes, timeout=10.0):
    """GET par socket Unix dedie d'un autre module (meme motif que secubox-hub pour
    secubox-netmodes) : forward l'en-tete Authorization recu — pas de second jeton."""
    import httpx

    with httpx.Client(transport=httpx.HTTPTransport(uds=socket_path)) as c:
        return c.get(f"http://localhost{chemin}", headers=entetes, timeout=timeout)


@app.get("/suggestions", dependencies=[Depends(require_jwt)])
def suggestions(request: Request):
    """Appareils vus par la Freebox non deja connus du NAC, avec une zone suggeree —
    jamais appliquee ici (#2940 spec section 4) : une liste pour decision du proprietaire."""
    from .classement import zone_suggeree

    entetes = {"Authorization": request.headers.get("authorization", "")}
    macs_connues = set()
    try:
        r = _appel_uds(NAC_SOCK, "/clients", entetes)
        if r.status_code == 200:
            macs_connues = {c.get("mac", "").lower() for c in r.json().get("clients", [])}
    except Exception:  # noqa: BLE001 — socket absent/lent ne doit jamais planter la requete
        pass
    non_classes = []
    try:
        r = _appel_uds(FREEBOX_SOCK, "/appareils-non-classes?macs_connues=" + ",".join(macs_connues), entetes)
        if r.status_code == 200:
            non_classes = r.json().get("appareils", [])
    except Exception:  # noqa: BLE001
        pass
    for a in non_classes:
        a["zone_suggeree"] = zone_suggeree(a.get("host_type"))
    return {"suggestions": non_classes}


@app.get("/journal", dependencies=[Depends(require_lecture)])
def journal(n: int = 50):
    """Dernieres bascules de passerelle DHCP, lues dans l'audit.log partage (action
    `passerelle_dhcp`, ecrite par secubox-freebox a chaque appel de pseudo-routeurctl)."""
    n = max(1, min(n, 500))
    entrees = []
    try:
        with open(AUDIT_LOG, "r") as f:
            for ligne in f:
                try:
                    d = json.loads(ligne)
                except json.JSONDecodeError:
                    continue
                if d.get("action") == "passerelle_dhcp":
                    entrees.append(d)
    except OSError:
        pass
    return {"entrees": entrees[-n:]}

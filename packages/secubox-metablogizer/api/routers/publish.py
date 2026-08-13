# packages/secubox-metablogizer/api/routers/publish.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""MetaBlogizer publisher wizard: upload -> version -> route -> cert -> backup."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

from publish.content import extract_archive, ContentError
from publish.routing import apply_route
from publish.certs import provision_cert
from publish.backup import export_site, import_site
from webhook import git_commit_push

# Derive sites_root from config the same way api/main.py does (importing from
# main would be circular since main imports this router).
_config = get_config("metablogizer")
SITES_ROOT = Path(_config.get("sites_root", "/srv/metablogizer/sites") if _config else "/srv/metablogizer/sites")
# Mirror the literal constants owned by api/main.py (kept in sync intentionally).
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
BASE_PORT = 8900

router = APIRouter()

# api/main.py DEPOSE ICI son générateur nginx, juste après l'avoir défini.
# L'importer serait circulaire — main importe ce routeur au chargement. Le
# crochet reste None dans les tests, qui n'ont pas de nginx à régénérer.
regenerer_nginx = None


def enregistre_domaine(site: Path, domaine: str) -> dict:
    """Écrit le domaine dans `site.json` (#1023).

    LE GENERATEUR NE LIT QUE LE DISQUE. `load_sites()` déduit le domaine de
    `site.json`, à défaut de `<nom>.gk2.secubox.in`. L'assistant acceptait un
    domaine en formulaire sans jamais l'écrire : il servait le temps d'une
    requête, puis disparaissait à la première régénération. Un réglage qu'on
    saisit et qui s'évapore est pire que pas de réglage du tout.
    """
    fichier = site / "site.json"
    doc = {}
    if fichier.exists():
        try:
            doc = json.loads(fichier.read_text())
            if not isinstance(doc, dict):
                doc = {}
        except (json.JSONDecodeError, OSError):
            # ON N'ECRASE PAS UN FICHIER QU'ON N'A PAS SU LIRE. Repartir d'un
            # document vide perdrait titre, version et catégorie du site.
            return {"ok": False, "detail": "site.json illisible, domaine non enregistré"}
    if doc.get("domain") == domaine:
        return {"ok": True, "detail": "déjà enregistré"}
    doc["domain"] = domaine
    doc.setdefault("name", site.name)
    try:
        tmp = fichier.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(fichier)
    except OSError as e:
        return {"ok": False, "detail": f"écriture site.json : {e}"}
    return {"ok": True, "detail": domaine}


def publie_vhost(domaine: str) -> dict:
    """Régénère la configuration nginx pour que le domaine soit SERVI (#1023).

    L'ETAPE MANQUANTE. L'assistant déposait le contenu, écrivait la route WAF,
    demandait le certificat — et s'arrêtait là. Aucun bloc `server` n'était créé.
    Or les 163 sites partagent le port 8900 et se distinguent par `server_name` :
    un domaine sans bloc ne tombe pas en erreur, il tombe sur LE PREMIER BLOC DU
    PORT. C'est ainsi que `www.gk2.secubox.in` a servi le site d'un voisin —
    chaque étape se déclarait réussie, et l'adresse montrait autre chose.
    """
    if regenerer_nginx is None:
        return {"ok": False, "detail": "générateur nginx indisponible"}
    try:
        ok, nombre, message = regenerer_nginx()
    except Exception as e:  # le générateur touche /etc et systemctl
        return {"ok": False, "detail": f"régénération nginx : {e}"}
    if not ok:
        return {"ok": False, "detail": message}
    return {"ok": True, "detail": message, "sites": nombre}


def _site_dir(name: str) -> Path:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "invalid site name")
    d = SITES_ROOT / name
    return d


@router.post("/publish/wizard")
async def publish_wizard(
    name: str = Form(...),
    domain: str = Form(None),
    file: UploadFile = File(...),
    user=Depends(require_jwt),
):
    site = _site_dir(name)
    docroot = site / "public"
    docroot.mkdir(parents=True, exist_ok=True)
    domain = domain or f"{name}{DEFAULT_DOMAIN_SUFFIX}"
    steps: dict = {}

    data = await file.read()
    try:
        steps["content"] = extract_archive(docroot, data, file.filename or "index.html")
    except ContentError as e:
        raise HTTPException(400, f"unsafe upload: {e}")

    steps["version"] = git_commit_push(site, f"publish {name} via wizard")
    # ORDRE VOULU : le domaine est enregistré AVANT la régénération, sans quoi
    # le générateur relit le disque et retombe sur `<nom>.gk2.secubox.in`.
    steps["domaine"] = enregistre_domaine(site, domain)
    steps["vhost"] = publie_vhost(domain)
    steps["route"] = apply_route(domain, BASE_PORT)
    steps["cert"] = provision_cert(domain)

    # `ok` EXIGE MAINTENANT QUE LE DOMAINE SOIT SERVI. Le compte rendu
    # d'origine se satisfaisait du contenu et de la route — un domaine sans
    # bloc `server` passait donc pour publié alors qu'il montrait le site du
    # voisin. Une étape qui n'entre pas dans le verdict ne protège de rien.
    ok = (bool(steps["content"].get("index_present"))
          and bool(steps["route"].get("route_ok"))
          and bool(steps["vhost"].get("ok")))
    return {"ok": ok, "domain": domain, "steps": steps}


class RouteRequest(BaseModel):
    domain: str
    port: int = BASE_PORT


@router.post("/publish/route")
async def publish_route(req: RouteRequest, user=Depends(require_jwt)):
    """Route an already-created site's domain through the WAF and provision its
    cert, WITHOUT a content upload. Used by the secubox-publish hub so it never
    writes /etc/nginx or /etc/haproxy itself (it runs unprivileged)."""
    route = apply_route(req.domain, req.port)
    cert = provision_cert(req.domain)
    return {"ok": bool(route.get("route_ok")), "route": route, "cert": cert}


@router.get("/publish/export/{name}")
async def publish_export(name: str, user=Depends(require_jwt)):
    site = _site_dir(name)
    if not site.exists():
        raise HTTPException(404, "site not found")
    manifest = {"name": name, "domain": f"{name}{DEFAULT_DOMAIN_SUFFIX}",
                "base_port": BASE_PORT}
    out = Path(tempfile.mkdtemp())
    art = export_site(site, manifest, out)
    return FileResponse(
        str(art), filename=art.name, media_type="application/octet-stream",
        background=BackgroundTask(shutil.rmtree, str(out), True),
    )


@router.post("/publish/import")
async def publish_import(file: UploadFile = File(...), user=Depends(require_jwt)):
    data = await file.read()
    tmp = Path(tempfile.mkdtemp())
    art = tmp / "upload.sbxsite"
    art.write_bytes(data)
    try:
        manifest = import_site(art, SITES_ROOT)
    except Exception as e:  # noqa: BLE001 — surface a clean 400
        raise HTTPException(400, f"import failed: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return JSONResponse({"ok": True, "manifest": manifest})

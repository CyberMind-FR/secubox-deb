# packages/secubox-metablogizer/api/routers/publish.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""MetaBlogizer publisher wizard: upload -> version -> route -> cert -> backup."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
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
    steps["route"] = apply_route(domain, BASE_PORT)
    steps["cert"] = provision_cert(domain)

    ok = bool(steps["content"].get("index_present")) and bool(steps["route"].get("route_ok"))
    return {"ok": ok, "domain": domain, "steps": steps}


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

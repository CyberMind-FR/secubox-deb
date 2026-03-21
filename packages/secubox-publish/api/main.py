"""SecuBox Publishing Platform - Unified Dashboard for Streamlit, StreamForge, Droplet, MetaBlogizer

Layer 2 orchestrator module that provides a unified interface to all publishing modules.
Follows the 2-layer architecture: simple UI -> aggregated API -> individual module APIs.
"""
import httpx
from typing import Dict, Any, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Publishing Platform")

# Module socket paths
MODULES = {
    "streamlit": "/run/secubox/streamlit.sock",
    "streamforge": "/run/secubox/streamforge.sock",
    "droplet": "/run/secubox/droplet.sock",
    "metablogizer": "/run/secubox/metablogizer.sock",
}


def _cfg():
    cfg = get_config("publish")
    return {
        "default_publisher": cfg.get("default_publisher", "droplet") if cfg else "droplet",
        "enable_streamlit": cfg.get("enable_streamlit", True) if cfg else True,
        "enable_streamforge": cfg.get("enable_streamforge", True) if cfg else True,
        "enable_droplet": cfg.get("enable_droplet", True) if cfg else True,
        "enable_metablogizer": cfg.get("enable_metablogizer", True) if cfg else True,
    }


async def _call_module(module: str, path: str, method: str = "GET", data: dict = None) -> dict:
    """Call a module's API via Unix socket."""
    socket_path = MODULES.get(module)
    if not socket_path:
        return {"error": f"Unknown module: {module}"}

    try:
        transport = httpx.HTTPTransport(uds=socket_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost") as client:
            if method == "GET":
                resp = await client.get(path, timeout=10)
            elif method == "POST":
                resp = await client.post(path, json=data or {}, timeout=30)
            elif method == "DELETE":
                resp = await client.delete(path, timeout=10)
            else:
                return {"error": f"Unsupported method: {method}"}
            return resp.json()
    except Exception as e:
        return {"error": str(e), "module": module}


# === Public Endpoints ===

@app.get("/status")
async def status():
    """Unified status for all publishing modules."""
    cfg = _cfg()
    statuses = {}

    for module in MODULES:
        if cfg.get(f"enable_{module}", True):
            result = await _call_module(module, "/status")
            statuses[module] = {
                "available": "error" not in result,
                "running": result.get("running", result.get("status") == "ok"),
                "details": result
            }

    running_count = sum(1 for s in statuses.values() if s.get("running"))

    return {
        "module": "publish",
        "status": "ok" if running_count > 0 else "degraded",
        "modules": statuses,
        "summary": {
            "total": len(statuses),
            "running": running_count,
        }
    }


# === Protected Endpoints ===

@app.get("/overview", dependencies=[Depends(require_jwt)])
async def overview():
    """Unified overview of all publishing content."""
    overview = {
        "apps": [],      # Streamlit apps
        "projects": [],  # StreamForge projects
        "files": [],     # Droplet files
        "sites": [],     # MetaBlogizer sites
    }

    # Streamlit apps
    result = await _call_module("streamlit", "/apps")
    if "apps" in result:
        overview["apps"] = result["apps"]

    # StreamForge projects
    result = await _call_module("streamforge", "/apps")
    if "apps" in result:
        overview["projects"] = result["apps"]

    # Droplet files
    result = await _call_module("droplet", "/list")
    if "files" in result:
        overview["files"] = result["files"]

    # MetaBlogizer sites
    result = await _call_module("metablogizer", "/sites")
    if "sites" in result:
        overview["sites"] = result["sites"]

    return overview


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def stats():
    """Publishing statistics across all modules."""
    overview = await overview()

    return {
        "streamlit": {
            "total_apps": len(overview.get("apps", [])),
            "running": sum(1 for a in overview.get("apps", []) if a.get("running")),
        },
        "streamforge": {
            "total_projects": len(overview.get("projects", [])),
        },
        "droplet": {
            "total_files": len(overview.get("files", [])),
            "published": sum(1 for f in overview.get("files", []) if f.get("published")),
        },
        "metablogizer": {
            "total_sites": len(overview.get("sites", [])),
            "published": sum(1 for s in overview.get("sites", []) if s.get("published")),
        }
    }


# === Streamlit Operations ===

@app.get("/streamlit/apps", dependencies=[Depends(require_jwt)])
async def streamlit_apps():
    """List Streamlit apps."""
    return await _call_module("streamlit", "/apps")


@app.post("/streamlit/deploy", dependencies=[Depends(require_jwt)])
async def streamlit_deploy(name: str):
    """Deploy a Streamlit app."""
    return await _call_module("streamlit", f"/app/{name}/start", "POST")


@app.post("/streamlit/stop", dependencies=[Depends(require_jwt)])
async def streamlit_stop(name: str):
    """Stop a Streamlit app."""
    return await _call_module("streamlit", f"/app/{name}/stop", "POST")


# === StreamForge Operations ===

@app.get("/streamforge/templates", dependencies=[Depends(require_jwt)])
async def streamforge_templates():
    """List StreamForge templates."""
    return await _call_module("streamforge", "/templates")


class CreateAppRequest(BaseModel):
    name: str
    template: str = "basic"


@app.post("/streamforge/create", dependencies=[Depends(require_jwt)])
async def streamforge_create(req: CreateAppRequest):
    """Create a new Streamlit app from template."""
    return await _call_module("streamforge", "/app", "POST", {"name": req.name, "template": req.template})


# === Droplet Operations ===

@app.get("/droplet/files", dependencies=[Depends(require_jwt)])
async def droplet_files():
    """List Droplet files."""
    return await _call_module("droplet", "/list")


class PublishRequest(BaseModel):
    file: str
    domain: str = None


@app.post("/droplet/publish", dependencies=[Depends(require_jwt)])
async def droplet_publish(req: PublishRequest):
    """Publish a file via Droplet."""
    return await _call_module("droplet", "/publish", "POST", {"file": req.file, "domain": req.domain})


# === MetaBlogizer Operations ===

@app.get("/metablogizer/sites", dependencies=[Depends(require_jwt)])
async def metablogizer_sites():
    """List MetaBlogizer sites."""
    return await _call_module("metablogizer", "/sites")


class CreateSiteRequest(BaseModel):
    name: str
    title: str = None


@app.post("/metablogizer/create", dependencies=[Depends(require_jwt)])
async def metablogizer_create(req: CreateSiteRequest):
    """Create a new static site."""
    return await _call_module("metablogizer", "/site", "POST", {"name": req.name, "title": req.title})


@app.post("/metablogizer/publish/{name}", dependencies=[Depends(require_jwt)])
async def metablogizer_publish(name: str):
    """Publish a static site."""
    return await _call_module("metablogizer", f"/site/{name}/publish", "POST")


# === Quick Actions ===

class QuickPublishRequest(BaseModel):
    content_type: str  # "app", "site", "file"
    name: str
    template: str = None
    data: dict = None


@app.post("/quick-publish", dependencies=[Depends(require_jwt)])
async def quick_publish(req: QuickPublishRequest):
    """Unified quick publish action.

    Simplifies the publishing workflow by auto-routing to the right module.
    This is the key Layer 2 abstraction for end-user simplicity.
    """
    if req.content_type == "app":
        # Create and deploy Streamlit app
        result = await _call_module("streamforge", "/app", "POST", {
            "name": req.name,
            "template": req.template or "basic"
        })
        if "error" not in result:
            await _call_module("streamlit", f"/app/{req.name}/start", "POST")
        return result

    elif req.content_type == "site":
        # Create and publish static site
        result = await _call_module("metablogizer", "/site", "POST", {
            "name": req.name,
            "title": req.data.get("title") if req.data else req.name
        })
        if "error" not in result:
            await _call_module("metablogizer", f"/site/{req.name}/publish", "POST")
        return result

    elif req.content_type == "file":
        # Publish via Droplet
        return await _call_module("droplet", "/publish", "POST", {
            "file": req.name,
            "domain": req.data.get("domain") if req.data else None
        })

    raise HTTPException(400, f"Unknown content type: {req.content_type}")

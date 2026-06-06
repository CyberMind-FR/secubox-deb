# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox API gateway — master ASGI app mounting per-module FastAPIs.

Each SecuBox module ships a `secubox_<name>.api.main` module exporting a
`FastAPI` instance named `app`. This aggregator imports each one and mounts
it under `/api/v1/<name>` so the single uvicorn process handles all routes.

Design constraints:

* **Isolation per module** — each `app.mount()` is wrapped in try/except so a
  broken module doesn't poison startup. Failures recorded in `_LOAD_ERRORS`
  visible at `/health`.
* **No code in modules changes** — sub-apps work as standalone uvicorn AND
  as mounted sub-apps. Modules with `app.on_event("startup")` keep working
  because FastAPI fires sub-app lifespan events on mount.
* **Path layout matches nginx convention** — nginx already routes
  `/api/v1/<name>/...` to the per-module unix socket. After migration, the
  same routes hit aggregator socket; the path-prefix mount preserves URLs.
* **Graceful degradation** — modules that fail to import don't take down
  the gateway. Their routes return 503 (FastAPI's default for unmounted).

Modules to mount are listed in /etc/secubox/aggregator.toml so the package
postinst can manage the migration set without code edits.
"""
from __future__ import annotations

import importlib
import logging
import sys
import tomllib
from pathlib import Path
from typing import Dict, List

from fastapi import FastAPI

log = logging.getLogger("secubox.aggregator")

CONFIG_FILE = Path("/etc/secubox/aggregator.toml")

# Path prefix preserved across all sub-app mounts. Matches existing nginx
# routes : `/api/v1/<module>/...`.
API_PREFIX = "/api/v1"

# Track which modules were successfully mounted and which failed.
_MOUNTED: List[str] = []
_LOAD_ERRORS: Dict[str, str] = {}


def _load_config() -> dict:
    """Read the TOML config. Returns a dict with at least 'modules' key.

    Default config (when file missing): empty module list — aggregator runs
    but mounts nothing. Lets the package install before modules are wired in.
    """
    cfg = {"modules": [], "version": __import__("aggregator").__version__}
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("rb") as f:
                data = tomllib.load(f)
            cfg["modules"] = list(data.get("modules", []))
            log.info("loaded %d modules from %s", len(cfg["modules"]), CONFIG_FILE)
        else:
            log.warning("no config at %s — aggregator runs with no mounts", CONFIG_FILE)
    except Exception as e:
        log.error("config load failed: %s", e)
    return cfg


SECUBOX_LIB = Path("/usr/lib/secubox")


def _load_app_from_path(name: str) -> FastAPI | None:
    """Locate the module's FastAPI by walking /usr/lib/secubox/<name>/.

    SecuBox modules ship their FastAPI as `api/main.py` (and the per-module
    systemd unit runs `uvicorn api.main:app` from cwd=/usr/lib/secubox/<name>).
    They are not installed as Python packages, so importlib.import_module
    can't find them — we load by absolute path via spec_from_file_location.

    The aggregator adds the module's directory to sys.path TEMPORARILY so
    relative imports inside `api/main.py` work (e.g. `from .deps import ...`).
    The path is popped after loading to avoid cross-module shadowing.
    """
    import importlib.util as _util

    candidates = [
        SECUBOX_LIB / name / "api" / "main.py",
        SECUBOX_LIB / name.replace("-", "_") / "api" / "main.py",
    ]
    target = next((p for p in candidates if p.exists()), None)
    if target is None:
        _LOAD_ERRORS[name] = f"main.py not found under {SECUBOX_LIB}/{{{name},{name.replace('-','_')}}}/api/"
        return None

    mod_dir = str(target.parent.parent)  # /usr/lib/secubox/<name>
    spec = _util.spec_from_file_location(f"sbx_mod_{name.replace('-', '_')}", target)
    if spec is None or spec.loader is None:
        _LOAD_ERRORS[name] = f"spec_from_file_location returned None for {target}"
        return None

    mod = _util.module_from_spec(spec)
    # Inject into sys.modules under a unique name so reloading/dependent
    # imports inside the module find it.
    sys.modules[spec.name] = mod
    # Add the module's parent dir to sys.path so its relative imports work.
    sys.path.insert(0, mod_dir)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        _LOAD_ERRORS[name] = f"exec_module: {type(e).__name__}: {e}"
        return None
    finally:
        try:
            sys.path.remove(mod_dir)
        except ValueError:
            pass

    sub_app = getattr(mod, "app", None)
    if not isinstance(sub_app, FastAPI):
        _LOAD_ERRORS[name] = "no FastAPI 'app' attribute at module level"
        return None
    return sub_app


def _mount_module(parent: FastAPI, name: str) -> None:
    """Resolve and mount a SecuBox module's FastAPI under /api/v1/<name>."""
    sub_app = _load_app_from_path(name)
    if sub_app is None:
        log.warning("[mount] %s SKIPPED — %s", name, _LOAD_ERRORS.get(name, "?"))
        return
    try:
        parent.mount(f"{API_PREFIX}/{name}", sub_app, name=name)
        _MOUNTED.append(name)
        log.info("[mount] %s OK at %s/%s", name, API_PREFIX, name)
    except Exception as e:
        _LOAD_ERRORS[name] = f"mount: {type(e).__name__}: {e}"
        log.error("[mount] %s FAILED on mount: %s", name, e)


def _build_app() -> FastAPI:
    cfg = _load_config()
    app = FastAPI(
        title="SecuBox API gateway",
        version=cfg.get("version", "0.1.0"),
        # Disable docs at root to avoid clashes — each sub-app keeps its own
        # /docs and /openapi.json under its mount path.
        docs_url=None,
        redoc_url=None,
    )

    for name in cfg.get("modules", []):
        _mount_module(app, name)

    @app.get("/health")
    def health() -> dict:
        """Aggregator health. Reports per-module load state."""
        return {
            "status": "ok",
            "mounted": _MOUNTED,
            "failed": _LOAD_ERRORS,
            "total_mounted": len(_MOUNTED),
            "total_failed": len(_LOAD_ERRORS),
        }

    @app.get("/")
    def root() -> dict:
        """Aggregator landing — minimal JSON for liveness probes."""
        return {
            "service": "secubox-aggregator",
            "version": cfg.get("version", "?"),
            "mounted": len(_MOUNTED),
            "failed": len(_LOAD_ERRORS),
        }

    return app


# uvicorn imports `secubox_aggregator.main:app` so this stays at module level
app = _build_app()

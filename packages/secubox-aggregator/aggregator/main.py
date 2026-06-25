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

    SecuBox modules ship their FastAPI as `api/main.py`. They are not
    installed as Python packages — the per-module systemd unit runs
    `uvicorn api.main:app` from cwd=/usr/lib/secubox/<name>, so module
    code typically uses one of these import styles :

        from .deps import X         # relative — needs __package__ set
        from api.deps import X      # absolute — needs cwd on sys.path
        from api import deps        # mixed
        import api.deps             # bare absolute

    To make all four work for many modules in the SAME interpreter we :

    1. Synthesise a per-module parent package `sbx_pkg_<safe>` whose
       __path__ is `<name>/api`. Loading api/main.py as `<pkg>.main`
       inside that synthetic package makes `from .deps` resolve to
       `sbx_pkg_<safe>.deps`, served from the right `api/` directory.
    2. Pop any cached `sys.modules["api"]` / `sys.modules["api.*"]` left
       behind by previously-loaded modules and put <name> on sys.path —
       so absolute `from api.X` resolves freshly to THIS module's `api/`.
    3. After exec, drop the freshly-loaded `api*` entries again so the
       next module starts with a clean slate (and remove the sys.path
       entry to prevent cross-module bleed).

    Both styles now work per-module without one module's `api/`
    shadowing another's — the bug that hit haproxy after auth had loaded.
    """
    import importlib.util as _util

    candidates = [
        SECUBOX_LIB / name / "api" / "main.py",
        SECUBOX_LIB / name.replace("-", "_") / "api" / "main.py",
    ]
    target = next((p for p in candidates if p.exists()), None)
    if target is None:
        _LOAD_ERRORS[name] = (
            f"main.py not found under "
            f"{SECUBOX_LIB}/{{{name},{name.replace('-', '_')}}}/api/"
        )
        return None

    api_dir = target.parent           # /usr/lib/secubox/<name>/api
    mod_dir = str(api_dir.parent)     # /usr/lib/secubox/<name>
    safe = name.replace("-", "_")
    pkg_name = f"sbx_pkg_{safe}"
    main_name = f"{pkg_name}.main"

    # ── (1) Synthetic parent package so `from .deps import X` works ──
    pkg_init = api_dir / "__init__.py"
    if pkg_init.exists():
        pkg_spec = _util.spec_from_file_location(
            pkg_name, pkg_init,
            submodule_search_locations=[str(api_dir)],
        )
    else:
        pkg_spec = _util.spec_from_loader(pkg_name, loader=None, is_package=True)
        pkg_spec.submodule_search_locations = [str(api_dir)]
    if pkg_spec is None:
        _LOAD_ERRORS[name] = "could not build synthetic parent package spec"
        return None
    pkg_mod = _util.module_from_spec(pkg_spec)
    pkg_mod.__path__ = [str(api_dir)]

    # ── (2) Isolate the `api` namespace from prior module loads ──
    for k in list(sys.modules):
        if k == "api" or k.startswith("api."):
            del sys.modules[k]
    sys.path.insert(0, mod_dir)
    sys.modules[pkg_name] = pkg_mod
    if pkg_init.exists() and pkg_spec.loader is not None:
        try:
            pkg_spec.loader.exec_module(pkg_mod)
        except Exception as e:
            _LOAD_ERRORS[name] = f"exec_module(parent): {type(e).__name__}: {e}"
            sys.modules.pop(pkg_name, None)
            try:
                sys.path.remove(mod_dir)
            except ValueError:
                pass
            return None

    # ── (3) Load api/main.py as `<pkg>.main` so it inherits __package__ ──
    spec = _util.spec_from_file_location(main_name, target)
    if spec is None or spec.loader is None:
        _LOAD_ERRORS[name] = f"spec_from_file_location returned None for {target}"
        return None
    mod = _util.module_from_spec(spec)
    mod.__package__ = pkg_name
    sys.modules[main_name] = mod
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
        # Drop any `api*` cache this load produced so the next module gets
        # its own fresh `api` namespace.
        for k in list(sys.modules):
            if k == "api" or k.startswith("api."):
                del sys.modules[k]

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

    @app.on_event("startup")
    async def _raise_threadpool() -> None:
        """Sync (`def`) route handlers — including the blocking ones converted
        by the #738 async-sweep — run in AnyIO's default threadpool (40 tokens).
        With ~110 modules sharing one process, raise the cap so concurrent
        blocking calls don't queue head-of-line behind a full pool."""
        try:
            import anyio
            anyio.to_thread.current_default_thread_limiter().total_tokens = 80
            log.info("threadpool limiter raised to 80 tokens")
        except Exception as e:  # never let this break startup
            log.warning("could not raise threadpool limiter: %s", e)

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

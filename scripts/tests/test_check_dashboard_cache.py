# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for scripts/check-dashboard-cache.py."""
from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

# Load the script as a module (hyphenated filename → import via spec loader).
_SCRIPT = Path(__file__).resolve().parents[1] / "check-dashboard-cache.py"
_spec = importlib.util.spec_from_file_location("cdc", _SCRIPT)
assert _spec and _spec.loader
cdc = importlib.util.module_from_spec(_spec)
sys.modules["cdc"] = cdc
_spec.loader.exec_module(cdc)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def make_fake_packages(root: Path, daemons: dict[str, str]) -> Path:
    """Materialise ``packages/<name>/api/main.py`` for each entry.

    ``daemons`` maps daemon-name → source code for ``main.py``.
    """
    pkg_root = root / "packages"
    pkg_root.mkdir()
    for name, src in daemons.items():
        d = pkg_root / name / "api"
        d.mkdir(parents=True)
        (d / "main.py").write_text(textwrap.dedent(src))
    return pkg_root


# ──────────────────────────────────────────────────────────────────────
# Core detection
# ──────────────────────────────────────────────────────────────────────

def test_compliant_handler_with_read_through_cache(tmp_path):
    """``stats_cache.get(...)`` in body → no finding."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-foo": """
            from fastapi import FastAPI
            app = FastAPI()
            stats_cache = object()  # placeholder; module-level instance
            @app.get("/stats")
            async def get_stats():
                cached = stats_cache.get("stats")
                if cached is not None:
                    return cached
                with open("/var/log/foo.log") as f:
                    return f.read()
        """,
    })
    reports, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert not unjustified
    assert len(reports[0].findings) == 0


def test_handler_doing_open_without_cache_is_flagged(tmp_path):
    pkg = make_fake_packages(tmp_path, {
        "secubox-bad": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats():
                with open("/var/log/foo.log") as f:
                    return f.read()
        """,
    })
    reports, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert len(unjustified) == 1
    f = unjustified[0]
    assert f.daemon == "secubox-bad"
    assert f.route == "/stats"
    assert any("open@" in c for c in f.io_calls)


def test_handler_doing_subprocess_run_is_flagged(tmp_path):
    pkg = make_fake_packages(tmp_path, {
        "secubox-bad": """
            import subprocess
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/metrics")
            async def get_metrics():
                return subprocess.run(["expensive"], capture_output=True)
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert len(unjustified) == 1
    assert "run@" in unjustified[0].io_calls[0]


def test_handler_with_no_io_is_compliant(tmp_path):
    """Pure in-memory handler doesn't need a cache."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-pure": """
            from fastapi import FastAPI
            app = FastAPI()
            STATE = {"x": 1}
            @app.get("/stats")
            async def get_stats():
                return STATE
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert not unjustified


def test_handler_with_bg_refresh_task_is_compliant(tmp_path):
    """``asyncio.create_task(refresh_cache())`` at startup covers all hot routes."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-bg": """
            import asyncio
            from fastapi import FastAPI
            app = FastAPI()

            async def refresh_cache():
                pass

            @app.on_event("startup")
            async def startup():
                asyncio.create_task(refresh_cache())

            @app.get("/stats")
            async def get_stats():
                with open("/var/log/foo.log") as f:
                    return f.read()
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert not unjustified


def test_handler_with_thread_refresh_is_compliant(tmp_path):
    """``threading.Thread(target=refresh_cache).start()`` — the SYNC background
    refresh idiom (sync FastAPI handler + daemon thread, e.g. secubox-frigate) —
    covers all hot routes just like the async create_task pattern."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-thread": """
            import threading
            from fastapi import FastAPI
            app = FastAPI()

            def refresh_cache():
                pass

            @app.on_event("startup")
            def startup():
                threading.Thread(target=refresh_cache, daemon=True).start()

            @app.get("/stats")
            def get_stats():
                from pathlib import Path
                return Path("/var/cache/foo.json").read_text()
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert not unjustified


def test_non_hot_route_is_not_audited(tmp_path):
    """``/health`` is NOT in HOT_ROUTES — even with I/O it should not flag."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-meh": """
            import subprocess
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/health")
            async def get_health():
                return subprocess.run(["systemctl", "is-active", "foo"])
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert not unjustified


def test_router_decorator_is_recognised(tmp_path):
    """``@router.get`` is treated like ``@app.get``."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-r": """
            from fastapi import APIRouter
            router = APIRouter()
            @router.get("/summary")
            async def get_summary():
                with open("/var/log/foo.log") as f:
                    return f.read()
        """,
    })
    _, unjustified = cdc.run(pkg, Path("/nonexistent"))
    assert len(unjustified) == 1
    assert unjustified[0].route == "/summary"


# ──────────────────────────────────────────────────────────────────────
# Allowlist
# ──────────────────────────────────────────────────────────────────────

def test_allowlist_suppresses_known_violation(tmp_path):
    pkg = make_fake_packages(tmp_path, {
        "secubox-bad": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats():
                with open("/var/log/foo.log") as f:
                    return f.read()
        """,
    })
    allowlist = tmp_path / "allow.toml"
    allowlist.write_text(textwrap.dedent("""
        [[entries]]
        daemon = "secubox-bad"
        route = "/stats"
        justification = "tracked in issue #999"
    """))
    reports, unjustified = cdc.run(pkg, allowlist)
    # Finding still recorded, but allowlist suppresses the failure
    assert len(reports[0].findings) == 1
    assert not unjustified


def test_allowlist_only_matches_exact_route(tmp_path):
    """Allowlisting daemon::/stats must not silence daemon::/alerts."""
    pkg = make_fake_packages(tmp_path, {
        "secubox-multi": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats():
                with open("/x") as f: f.read()
            @app.get("/alerts")
            async def get_alerts():
                with open("/y") as f: f.read()
        """,
    })
    allowlist = tmp_path / "allow.toml"
    allowlist.write_text(textwrap.dedent("""
        [[entries]]
        daemon = "secubox-multi"
        route = "/stats"
        justification = "x"
    """))
    _, unjustified = cdc.run(pkg, allowlist)
    assert len(unjustified) == 1
    assert unjustified[0].route == "/alerts"


def test_missing_allowlist_file_is_ignored(tmp_path):
    pkg = make_fake_packages(tmp_path, {
        "secubox-pure": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats(): return {}
        """,
    })
    reports, unjustified = cdc.run(pkg, tmp_path / "does-not-exist.toml")
    assert not unjustified
    assert len(reports) == 1


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def test_cli_check_exits_1_on_unjustified(tmp_path, capsys):
    pkg = make_fake_packages(tmp_path, {
        "secubox-bad": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats():
                with open("/x") as f: f.read()
        """,
    })
    rc = cdc.main(["--check", "--packages", str(pkg),
                   "--allowlist", str(tmp_path / "noop.toml")])
    out = capsys.readouterr().out
    assert rc == 1
    assert "unjustified violation" in out


def test_cli_check_exits_0_when_clean(tmp_path):
    pkg = make_fake_packages(tmp_path, {
        "secubox-ok": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats(): return {}
        """,
    })
    rc = cdc.main(["--check", "--packages", str(pkg),
                   "--allowlist", str(tmp_path / "noop.toml")])
    assert rc == 0


def test_cli_json_output(tmp_path, capsys):
    pkg = make_fake_packages(tmp_path, {
        "secubox-bad": """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/stats")
            async def get_stats():
                with open("/x") as f: f.read()
        """,
    })
    rc = cdc.main(["--json", "--packages", str(pkg),
                   "--allowlist", str(tmp_path / "noop.toml")])
    out = capsys.readouterr().out
    import json as _json
    data = _json.loads(out)
    assert rc == 0  # --json doesn't exit non-zero (only --check does)
    assert data["summary"]["unjustified_violations"] == 1
    assert data["unjustified"][0]["daemon"] == "secubox-bad"


# ──────────────────────────────────────────────────────────────────────
# Repo integration
# ──────────────────────────────────────────────────────────────────────

def test_real_repo_with_seeded_allowlist_passes_check():
    """Sanity: running on the real packages/ with .cache-lint-allowlist.toml
    must be clean. Catches regressions if someone adds a new violation
    or removes an allowlist entry without fixing the daemon."""
    repo = Path(__file__).resolve().parents[2]
    rc = cdc.main(["--check",
                   "--packages", str(repo / "packages"),
                   "--allowlist", str(repo / ".cache-lint-allowlist.toml")])
    assert rc == 0, "real repo audit must pass with seeded allowlist"

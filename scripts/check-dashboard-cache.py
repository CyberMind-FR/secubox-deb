# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""scripts/check-dashboard-cache.py — double-cache pattern lint.

Audits every ``packages/secubox-*/api/main.py`` to verify that endpoints
serving aggregate / log-derived data (``/stats``, ``/alerts``,
``/summary``, ``/dashboard``, ``/metrics``, ``/overview``) read from a
cache and don't perform unbounded I/O on every request.

The pattern is documented in ``CLAUDE.md`` (« Performance Patterns —
Double Caching ») and the canonical implementation lives in
``packages/secubox-crowdsec/api/main.py`` (``StatsCache`` class).

A handler is **compliant** when at least one of these holds:

1. Its body calls ``<something>_cache.get(...)`` (read-through cache) AND
   the module instantiates a cache (any name ending in ``_cache``).
2. The module starts an ``asyncio.create_task(refresh_*)`` at startup
   (background-refresh pattern).
3. The handler body contains zero I/O ops (``open``, ``read_text``,
   ``read_bytes``, ``subprocess.run``, ``Popen``) — pure in-memory.
4. The ``daemon::endpoint`` pair is in
   ``.cache-lint-allowlist.toml`` with a written justification (typically
   for cheap ``systemctl is-active``-style ``/status`` endpoints).

Usage::

    python3 scripts/check-dashboard-cache.py --check   # CI, exit 1 on violation
    python3 scripts/check-dashboard-cache.py --report  # full triage table
    python3 scripts/check-dashboard-cache.py --json    # machine-readable

Designed to be wired into ``.github/workflows/dashboard-cache-check.yml``
exactly like ``license-check.yml`` does for SPDX headers.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

try:
    import tomllib  # 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────

# Endpoints that consume aggregate/log-derived data and are typically
# polled by dashboards. A handler attached to one of these via
# @app.get / @router.get must be cache-backed.
HOT_ROUTES = frozenset({
    "/stats",
    "/alerts",
    "/summary",
    "/dashboard",
    "/metrics",
    "/overview",
    "/events",
    "/history",
    "/recent",
    "/bans",
    "/sessions",
    "/connections",
})

# Callables in a handler body that indicate per-request I/O.
IO_CALLABLES = frozenset({
    "open",
    "read_text",
    "read_bytes",
    "loads",          # json.loads of a freshly-read file — flagged when paired with open in chain
    "run",            # subprocess.run
    "Popen",
    "check_output",
    "check_call",
    "communicate",
})

# Decorator names that mount HTTP handlers we care about.
ROUTE_DECORATORS = frozenset({"get", "post"})

DEFAULT_ALLOWLIST_PATH = Path(".cache-lint-allowlist.toml")
DEFAULT_PACKAGES_ROOT = Path("packages")


# ─────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    daemon: str
    file: Path
    line: int
    route: str
    handler: str
    io_calls: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        """daemon::route — the allowlist key."""
        return f"{self.daemon}::{self.route}"


@dataclass
class DaemonReport:
    daemon: str
    file: Path
    has_cache_instance: bool
    has_bg_refresh: bool
    findings: list[Finding] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────
# AST analysis
# ─────────────────────────────────────────────────────────────────────

def _decorator_route(dec: ast.expr) -> tuple[Optional[str], Optional[str]]:
    """Return (verb, path) if ``dec`` is ``@app.get("/x")`` or
    ``@router.post("/x")``, else (None, None)."""
    if not isinstance(dec, ast.Call):
        return None, None
    func = dec.func
    if not isinstance(func, ast.Attribute) or func.attr not in ROUTE_DECORATORS:
        return None, None
    if not isinstance(func.value, ast.Name) or func.value.id not in {"app", "router"}:
        return None, None
    if not dec.args:
        return None, None
    arg0 = dec.args[0]
    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
        return func.attr, arg0.value
    return None, None


def _is_hot(path: str) -> bool:
    """Match a route path against HOT_ROUTES, treating ``/foo/{x}`` as
    ``/foo`` so e.g. ``/stats/by_ip`` is *not* matched but ``/stats``
    is."""
    if path in HOT_ROUTES:
        return True
    # Allow ``/stats/`` or ``/stats`` exact match; sub-paths require
    # explicit inclusion to keep the lint focused on the canonical
    # dashboard surface.
    return False


def _collect_io_in_body(body: list[ast.stmt]) -> list[str]:
    """Return list of ``func_name@line`` strings for each I/O callable."""
    hits: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            name: Optional[str] = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in IO_CALLABLES:
                # Filter false positives: ``json.loads(some_string)`` is fine,
                # but ``json.loads(p.read_text())`` is already caught by the
                # ``read_text`` hit, and bare ``loads`` of a constant we don't
                # care about. Conservatively flag ``loads`` only when nested
                # alongside ``read_text``/``open``.
                if name == "loads":
                    # Skip — too noisy on its own; ``read_text`` will fire
                    # when the source is a freshly-read file.
                    return self.generic_visit(node)
                hits.append(f"{name}@L{node.lineno}")
            self.generic_visit(node)

    for stmt in body:
        Visitor().visit(stmt)
    return hits


def _module_signals(tree: ast.Module) -> tuple[bool, bool]:
    """Return (has_cache_instance, has_bg_refresh).

    - has_cache_instance: a module-level assignment whose target is a
      Name ending in ``_cache`` (e.g. ``stats_cache = StatsCache(...)``).
    - has_bg_refresh: a background refresh spawner, either
        * ``asyncio.create_task(refresh_*())`` (async idiom), or
        * ``threading.Thread(target=refresh_*)`` / ``Thread(target=refresh_*)``
          (the sync idiom — a daemon thread refreshing a module-level cache,
          used by sync FastAPI handlers, e.g. secubox-frigate),
      where the spawned callable's name contains ``refresh`` / ``cache`` /
      ``poll`` / ``loop`` / ``periodic``.
    """
    _BG_KW = ("refresh", "cache", "poll", "loop", "periodic")

    def _name_of(n) -> str:
        return (n.id if isinstance(n, ast.Name)
                else n.attr if isinstance(n, ast.Attribute) else "")

    has_cache = False
    has_bg = False

    for node in ast.walk(tree):
        # Cache instance detection
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id.endswith("_cache"):
                    has_cache = True
        # Background refresh detection
        if isinstance(node, ast.Call):
            func = node.func
            # (a) asyncio.create_task(refresh_*())
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "create_task"
                and isinstance(func.value, ast.Name)
                and func.value.id == "asyncio"
            ):
                if node.args and isinstance(node.args[0], ast.Call):
                    inner_name = _name_of(node.args[0].func)
                    if any(kw in inner_name.lower() for kw in _BG_KW):
                        has_bg = True
            # (b) threading.Thread(target=refresh_*) or Thread(target=refresh_*)
            if (isinstance(func, ast.Attribute) and func.attr == "Thread") or \
               (isinstance(func, ast.Name) and func.id == "Thread"):
                for kw in node.keywords:
                    if kw.arg == "target":
                        tgt_name = _name_of(kw.value)
                        if any(k in tgt_name.lower() for k in _BG_KW):
                            has_bg = True

    return has_cache, has_bg


def _handler_uses_cache(body: list[ast.stmt]) -> bool:
    """True if the handler body calls ``something_cache.get(...)``."""
    class Visitor(ast.NodeVisitor):
        found = False

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            if isinstance(node.func, ast.Attribute) and node.func.attr == "get":
                val = node.func.value
                if isinstance(val, ast.Name) and val.id.endswith("_cache"):
                    self.found = True
            self.generic_visit(node)

    v = Visitor()
    for stmt in body:
        v.visit(stmt)
    return v.found


def audit_daemon(main_py: Path, daemon_name: str) -> DaemonReport:
    """Audit one ``packages/<daemon>/api/main.py``."""
    src = main_py.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(src, filename=str(main_py))

    has_cache, has_bg = _module_signals(tree)
    report = DaemonReport(
        daemon=daemon_name,
        file=main_py,
        has_cache_instance=has_cache,
        has_bg_refresh=has_bg,
    )

    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for dec in node.decorator_list:
            verb, path = _decorator_route(dec)
            if not path or not _is_hot(path):
                continue

            io_hits = _collect_io_in_body(node.body)
            if not io_hits:
                # Pure handler — compliant by trivial absence of I/O
                continue
            if has_bg:
                # Background-refresh pattern covers all hot routes globally
                continue
            if _handler_uses_cache(node.body):
                # Explicit read-through cache check
                continue

            report.findings.append(Finding(
                daemon=daemon_name,
                file=main_py,
                line=node.lineno,
                route=path,
                handler=node.name,
                io_calls=io_hits,
            ))
            break  # one decorator is enough per function

    return report


# ─────────────────────────────────────────────────────────────────────
# Allowlist
# ─────────────────────────────────────────────────────────────────────

def load_allowlist(path: Path) -> dict[str, str]:
    """Return ``{ "daemon::/route": "justification" }`` from TOML."""
    if not path.is_file():
        return {}
    with path.open("rb") as f:
        data = tomllib.load(f)
    entries = data.get("entries", [])
    return {f"{e['daemon']}::{e['route']}": e.get("justification", "") for e in entries}


# ─────────────────────────────────────────────────────────────────────
# Driver
# ─────────────────────────────────────────────────────────────────────

def find_main_files(packages_root: Path) -> Iterable[tuple[str, Path]]:
    """Yield (daemon_name, path) for each ``packages/*/api/main.py``."""
    for pkg in sorted(packages_root.iterdir()):
        if not pkg.is_dir():
            continue
        main = pkg / "api" / "main.py"
        if main.is_file():
            yield pkg.name, main


def run(packages_root: Path, allowlist_path: Path) -> tuple[list[DaemonReport], list[Finding]]:
    """Run the audit. Returns (all_reports, unjustified_findings)."""
    allowlist = load_allowlist(allowlist_path)
    all_reports: list[DaemonReport] = []
    unjustified: list[Finding] = []

    for daemon, main in find_main_files(packages_root):
        rep = audit_daemon(main, daemon)
        all_reports.append(rep)
        for f in rep.findings:
            if f.key not in allowlist:
                unjustified.append(f)

    return all_reports, unjustified


# ─────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────

def format_report(
    reports: list[DaemonReport],
    unjustified: list[Finding],
    allowlist_path: Path,
) -> str:
    lines: list[str] = []
    n_compliant = sum(1 for r in reports if not r.findings)
    n_violating = len(reports) - n_compliant
    lines.append(f"Audited {len(reports)} daemons "
                 f"({n_compliant} compliant, {n_violating} with findings).")
    lines.append("")
    if not reports:
        return "\n".join(lines)
    for r in reports:
        if not r.findings:
            continue
        sig = []
        if r.has_cache_instance: sig.append("cache-instance")
        if r.has_bg_refresh: sig.append("bg-refresh")
        sig_str = ",".join(sig) if sig else "no-cache-signals"
        lines.append(f"  {r.daemon} [{sig_str}]")
        for f in r.findings:
            allowlisted = " [ALLOWLISTED]" if f.key not in {u.key for u in unjustified} else ""
            lines.append(f"    {f.file}:{f.line} {f.route} ({f.handler}) "
                         f"io={','.join(f.io_calls)}{allowlisted}")
    lines.append("")
    if unjustified:
        lines.append(f"❌ {len(unjustified)} unjustified violation(s). "
                     f"Either implement the double-cache pattern (see "
                     f"packages/secubox-crowdsec/api/main.py:106-138 for the "
                     f"reference StatsCache class) or add a justified entry to "
                     f"{allowlist_path}.")
    else:
        lines.append("✓ No unjustified violations.")
    return "\n".join(lines)


def format_json(reports: list[DaemonReport], unjustified: list[Finding]) -> str:
    out = {
        "summary": {
            "daemons_audited": len(reports),
            "with_findings": sum(1 for r in reports if r.findings),
            "unjustified_violations": len(unjustified),
        },
        "daemons": [
            {
                "name": r.daemon,
                "file": str(r.file),
                "has_cache_instance": r.has_cache_instance,
                "has_bg_refresh": r.has_bg_refresh,
                "findings": [
                    {
                        "route": f.route,
                        "handler": f.handler,
                        "line": f.line,
                        "io_calls": f.io_calls,
                    }
                    for f in r.findings
                ],
            }
            for r in reports
        ],
        "unjustified": [
            {"daemon": f.daemon, "route": f.route, "file": str(f.file), "line": f.line}
            for f in unjustified
        ],
    }
    return json.dumps(out, indent=2)


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--packages", type=Path, default=DEFAULT_PACKAGES_ROOT,
                        help="path to packages/ root (default: packages)")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST_PATH,
                        help="TOML allowlist for justified violations")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true",
                   help="exit 1 on unjustified violations (for CI)")
    g.add_argument("--report", action="store_true",
                   help="print full triage table (default)")
    g.add_argument("--json", action="store_true", dest="as_json",
                   help="machine-readable output")
    args = parser.parse_args(argv)

    if not args.packages.is_dir():
        print(f"error: --packages {args.packages} not a directory", file=sys.stderr)
        return 2

    reports, unjustified = run(args.packages, args.allowlist)

    if args.as_json:
        print(format_json(reports, unjustified))
    else:
        print(format_report(reports, unjustified, args.allowlist))

    if args.check and unjustified:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

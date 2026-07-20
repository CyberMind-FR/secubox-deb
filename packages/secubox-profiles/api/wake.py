# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — secubox-wakectl : réveille UN module (start on-demand)
CyberMind — https://cybermind.fr

Ne réimplémente rien : construit un plan START pour le module ciblé et le
confie à l'actionneur 0.7.0 (apply_plan, état-observé, snapshot 4R, audit,
timeout dérivé). Refuse manual/unknown/always-on. Idempotent si déjà up.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import apply as _apply
from .actuate import TIMED_OUT
from .actuate_paths import DEFAULT_ROOT
from .actuate_paths import audit_path_for as _audit_path_for
from .actuate_paths import snap_root_for as _snap_root_for
from .diff import START, Change
from .lifecycle import effective_lifecycle
from .manifest import load_all
from .observe import is_on, observe as _observe


def wake(module: str, *, root: Path = DEFAULT_ROOT, run, observe=_observe,
         now: str, apply: bool = True) -> dict:
    """Réveille `module` : refuse manual/unknown/always-on, no-op si déjà up,
    sinon construit un plan START d'un seul élément et le confie à
    apply.apply_plan (snapshot 4R + audit + timeout dérivé + rollback en cas
    d'échec — tout est délégué, wake ne pilote jamais systemd/lxc lui-même)."""
    root = Path(root)
    manifests = load_all(root / "modules.d")
    m = manifests.get(module)
    if m is None:
        return {"status": "refused", "module": module, "reason": "unknown"}
    eff = effective_lifecycle(m)
    if eff in ("manual", "always-on"):
        # manual: jamais de réveil auto. always-on: déjà censé tourner (rien à réveiller).
        return {"status": "refused", "module": module, "reason": eff}
    if is_on(observe(m)):
        return {"status": "already-up", "module": module}
    plan = [Change(module, START, "wake-on-access", m.priority)]
    actuals = {module: observe(m)}
    report = _apply.apply_plan(plan, manifests, actuals, run=run, observe=observe,
                               now=now, routes={}, snap_root=_snap_root_for(root),
                               audit_path=_audit_path_for(root), apply=apply)
    if report.status == "applied" and module in report.changed:
        return {"status": "woken", "module": module}
    if report.status == "planned":
        # apply=False (dry-run) : apply_plan n'a rien exécuté, ce n'est pas
        # un échec — rien n'a été tenté.
        return {"status": "planned", "module": module}
    return {"status": "failed", "module": module,
            "failed": report.failed, "rolled_back": report.rolled_back}


def _run(argv: list[str]) -> tuple[int | None, str]:
    import subprocess
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired:
        return TIMED_OUT, ""
    except OSError:
        return None, ""


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _running_as_root() -> bool:
    return os.geteuid() == 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secubox-wakectl")
    p.add_argument("--root", default=str(DEFAULT_ROOT))
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("wake")
    sp.add_argument("module")
    sp.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not _running_as_root():
        print("wake doit être lancé en root (il pilote systemd/LXC).", file=sys.stderr)
        return 1
    rep = wake(args.module, root=Path(args.root), run=_run, now=_now_iso())
    if args.json:
        print(json.dumps(rep))
    else:
        print(f"wake[{args.module}]: {rep['status']}")
    return {"woken": 0, "already-up": 0, "refused": 3, "failed": 2}.get(rep["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())

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
from . import portal_routes as _portal_routes
from .actuate import TIMED_OUT
from .actuate_paths import DEFAULT_ROOT
from .actuate_paths import audit_path_for as _audit_path_for
from .actuate_paths import remember_path_for as _remember_path_for
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
    # Route WAF d'un module portail : disparue du fichier vivant depuis
    # l'endormissement, on la relit dans la mémoire durable (remember au STOP).
    # apply_plan la capture dans le snapshot → l'actionneur la restaure au START.
    routes = {}
    if m.portal_domain:
        remembered = _portal_routes.recall(m.portal_domain,
                                           path=_remember_path_for(root))
        if remembered is not None:
            routes[m.portal_domain] = remembered
    report = _apply.apply_plan(plan, manifests, actuals, run=run, observe=observe,
                               now=now, routes=routes, snap_root=_snap_root_for(root),
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
    sp2 = sub.add_parser("nginx-sync")
    sp2.add_argument("--sites", default="/etc/nginx/sites-available")
    # Sans --all, seuls les modules « a la demande » sont cables : tous les
    # autres vhosts gardent la page BRUTE de nginx sur un 502.
    sp2.add_argument("--all", action="store_true",
                     help="cabler TOUS les vhosts qui relaient, pas seulement les on-demand")
    sp3 = sub.add_parser("waf-sync")
    sp3.add_argument("--out", default="/etc/secubox/waf/on-demand-vhosts.json")
    sp4 = sub.add_parser("health-sync")
    sp4.add_argument("--out", default="/etc/secubox/health/sleepable-modules.json")
    args = p.parse_args(argv)
    if args.cmd == "nginx-sync":
        from . import nginxgen
        if not _running_as_root():
            print("nginx-sync doit être lancé en root (édite /etc/nginx + reload).",
                  file=sys.stderr)
            return 1
        rep = nginxgen.sync_and_reload(
            manifests=load_all(Path(args.root) / "modules.d"),
            sites_dir=Path(args.sites), run=_run, all_vhosts=args.all)
        print(f"nginx-sync: {len(rep['wired'])} câblé(s), {len(rep['already'])} déjà, "
              f"{len(rep['no_config'])} sans vhost"
              + (" — ROLLBACK (nginx -t a échoué)" if rep["rolled_back"] else ""))
        if rep["no_config"]:
            print(f"  on-demand sans vhost nginx : {', '.join(rep['no_config'])}",
                  file=sys.stderr)
        return 1 if rep["rolled_back"] else 0
    if args.cmd == "waf-sync":
        from . import wafsync
        doms = wafsync.write_ondemand(manifests=load_all(Path(args.root) / "modules.d"),
                                       out_path=Path(args.out))
        print(f"waf-sync: {len(doms)} vhost(s) — {', '.join(doms) or 'aucun'}")
        return 0
    if args.cmd == "health-sync":
        from . import healthsync
        ids = healthsync.write_sleepable(manifests=load_all(Path(args.root) / "modules.d"),
                                          out_path=Path(args.out))
        print(f"health-sync: {len(ids)} module(s) sleepable — {', '.join(ids) or 'aucun'}")
        return 0
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

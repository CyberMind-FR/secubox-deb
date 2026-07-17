# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — CLI secubox-profilectl
CyberMind — https://cybermind.fr

Phase 1 : LECTURE SEULE. `scan`, `status`, `diff` — et rien d'autre. `apply`
n'existe pas encore : il arrive en Phase 3, avec snapshot 4R, application
séquentielle et audit.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .diff import ProtectedViolation, plan_changes
from .manifest import ManifestError, load_all
from .observe import Actual, is_on, load_routes, observe
from .scan import discover, write_drafts
from .state import StateError, load_pins, load_profile

DEFAULT_ROOT = Path("/etc/secubox")


def _paths(root: Path):
    return (root / "modules.d", root / "profiles",
            root / "profiles" / "pins.toml", root / "profiles" / "active")


def _observe_all(manifests, routes):
    return {mid: observe(m, routes=routes) for mid, m in manifests.items()}


def _active_profile_name(root: Path, override: str | None) -> str | None:
    if override:
        return override
    _, _, _, active = _paths(root)
    if active.exists():
        name = active.read_text(encoding="utf-8").strip()
        return name or None
    return None


def _load_profile_or_none(root: Path, name: str | None):
    if not name:
        return None
    _, prof_dir, _, _ = _paths(root)
    p = prof_dir / f"{name}.toml"
    if not p.exists():
        raise StateError(f"profil inconnu: {name} ({p} absent)")
    return load_profile(p)


def _cmd_status(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    routes = load_routes()
    actuals = _observe_all(manifests, routes)
    rows = []
    for mid, m in sorted(manifests.items()):
        a = actuals.get(mid, Actual())
        rows.append({
            "id": mid, "category": m.category, "runtime": m.runtime,
            "exposure": m.exposure, "priority": m.priority,
            "protected": m.protected, "on": is_on(a), "rss_kb": a.rss_kb,
        })
    if args.json:
        print(json.dumps({"modules": rows}, ensure_ascii=False))
        return 0
    for r in sorted(rows, key=lambda r: (-r["priority"], r["id"])):
        rss = f"{r['rss_kb'] / 1024:.0f} Mo" if r["rss_kb"] else "—"
        print(f"{'🟢' if r['on'] else '⚫'} {r['id']:<20} {r['category']:<9} "
              f"{r['runtime']:<7} {r['exposure']:<9} prio={r['priority']:<3} {rss:>8}"
              f"{'  🔒' if r['protected'] else ''}")
    return 0


def _cmd_diff(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    profile = _load_profile_or_none(root, _active_profile_name(root, args.profile))
    pins = load_pins(pins_file)
    actuals = _observe_all(manifests, load_routes())
    changes = plan_changes(manifests, profile, pins, actuals)
    payload = [{"id": c.id, "action": c.action, "priority": c.priority,
                "reason": c.reason} for c in changes]
    if args.json:
        print(json.dumps({"changes": payload}, ensure_ascii=False))
        return 0
    if not changes:
        print("✅ rien à changer — l'état réel correspond déjà au profil.")
        return 0
    print(f"{len(changes)} changement(s) — Phase 1 n'applique rien :")
    for c in changes:
        print(f"  {'⛔ stop ' if c.action == 'stop' else '▶️  start'} {c.id:<20} ({c.reason})")
    return 0


def _cmd_scan(args) -> int:
    root = Path(args.root)
    mod_dir, _, _, _ = _paths(root)
    rc, out = _run(["systemctl", "list-unit-files", "secubox-*.service",
                    "--no-legend", "--plain"])
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    rc, out = _run(["lxc-ls", "-1"])
    lxc_names = {n.strip() for n in out.splitlines() if n.strip()}
    # load_routes() renvoie None quand le fichier de routes existe mais est
    # illisible/corrompu (indéterminable) — discover() attend un set() ferme,
    # donc on retombe sur "aucune route connue" plutôt que de propager le None
    # (qui ferait planter `for r in sorted(routes)` dans scan._route_for).
    manifests = discover(units=units, lxc_names=lxc_names, routes=load_routes() or set())
    written = write_drafts(manifests, mod_dir, force=args.force)
    skipped = len(manifests) - len(written)
    print(f"{len(manifests)} module(s) découvert(s) — {len(written)} manifeste(s) écrit(s), "
          f"{skipped} conservé(s) (déjà présents ; --force pour écraser).")
    return 0


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="secubox-profilectl",
        description="Inventaire et diff des modules SecuBox (Phase 1 : lecture seule).")
    p.add_argument("--root", default=str(DEFAULT_ROOT),
                   help="racine de config (défaut: /etc/secubox)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("status", help="état et coût de chaque module")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_status)

    sp = sub.add_parser("diff", help="ce qu'un profil changerait (n'applique rien)")
    sp.add_argument("--profile", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_diff)

    sp = sub.add_parser("scan", help="dériver les manifestes du réel")
    sp.add_argument("--force", action="store_true",
                    help="écraser les manifestes existants (ils font autorité par défaut)")
    sp.set_defaults(func=_cmd_scan)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ManifestError, StateError) as exc:
        print(f"erreur: {exc}", file=sys.stderr)
        return 2
    except ProtectedViolation as exc:
        print(f"refusé: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

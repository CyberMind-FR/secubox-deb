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
import os
import subprocess
import sys
from pathlib import Path

from . import export
from .diff import ProtectedViolation, plan_changes
from .export import format_apt, format_json, format_pkglist, resolve_packages
from .manifest import ManifestError, load_all
from .observe import Actual, is_on, load_routes, observe_all
from .scan import discover, write_drafts
from .state import StateError, load_pins, load_profile

DEFAULT_ROOT = Path("/etc/secubox")


def _paths(root: Path):
    return (root / "modules.d", root / "profiles",
            root / "profiles" / "pins.toml", root / "profiles" / "active")


def _observe_all(manifests, routes):
    """Point d'entrée partagé par `status`/`diff` (CLI) et par le calcul de
    cache de l'API web (voir api/web.py) — batché (observe.observe_all), pas
    une boucle observe() par module : sur 187 modules, la boucle coûtait
    ~46s (560 sous-process) contre <1s batché (mesuré sur la board). observe()
    module par module reste la référence (tests, sondage d'un seul module) ;
    ce wrapper n'en change pas le contrat, seulement le coût."""
    return observe_all(manifests, routes=routes)


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
    mod_dir, _, _, _ = _paths(root)
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


def _cmd_export(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    profile = _load_profile_or_none(root, args.profile)  # StateError -> rc 2 if unknown
    pins = load_pins(pins_file)
    actuals = _observe_all(manifests, load_routes())
    rss_kb = {mid: (a.rss_kb or 0) for mid, a in actuals.items()}
    # run=export._run (attribut, pas la valeur par défaut de resolve_packages)
    # pour que le monkeypatch de export._run dans les tests (et un futur run
    # alternatif) soit bien pris en compte : le défaut de resolve_packages a
    # été figé à l'import de export.py, une réaffectation de export._run après
    # coup ne le changerait pas si on ne passait pas explicitement l'attribut.
    result = resolve_packages(manifests, profile, pins, run=export._run, rss_kb=rss_kb)
    if result.unresolved:
        print("⚠️  paquet introuvable pour: " + ", ".join(result.unresolved)
              + " — exclus de la liste (installateur incomplet).", file=sys.stderr)
    fmt = {"pkglist": format_pkglist, "apt": format_apt, "json": format_json}[args.format]
    print(fmt(result))
    return 0


def _running_as_root() -> bool:
    return os.geteuid() == 0


def _cmd_scan(args) -> int:
    root = Path(args.root)
    mod_dir, _, _, _ = _paths(root)

    rc, out = _run(["systemctl", "list-unit-files", "secubox-*.service",
                    "--no-legend", "--plain"])
    # rc=None (n'a pas pu s'exécuter) ou rc!=0 (a répondu par un échec) sont
    # tous deux des cas indéterminés : on ne peut pas distinguer "aucune unit
    # secubox-*" (out="", rc=0, cas normal) de "systemctl a échoué" sans
    # regarder rc. Continuer sur out="" écrirait silencieusement zéro
    # manifeste en laissant croire que le scan a réussi.
    if rc != 0:
        print(f"⚠️  systemctl list-unit-files a échoué (rc={rc!r}) — impossible "
              "d'énumérer les units secubox-*.service. scan ne peut pas "
              "produire un inventaire fiable dans cet état ; corrigez systemd "
              "puis relancez `scan`.", file=sys.stderr)
        return 1
    units = [line.split()[0] for line in out.splitlines() if line.strip()]

    # lxc-ls non-root répond rc=0 avec une sortie vide (silencieuse) plutôt
    # qu'une erreur — indistinguable d'une box sans conteneur. Sur cette box
    # (24 conteneurs LXC), ça déclasserait silencieusement tous les modules
    # LXC en runtime="native" dans un manifeste qui fait ensuite autorité :
    # Phase 3 ne lancerait alors jamais `lxc-stop` sur eux. On refuse plutôt
    # que d'écrire un inventaire qu'on sait potentiellement faux.
    if not _running_as_root():
        print("⚠️  scan doit être lancé en root : sans privilèges, `lxc-ls` "
              "renvoie une liste vide (rc=0, pas une erreur) et scan "
              "dériverait à tort tous les conteneurs LXC en runtime=\"native\" "
              "dans un manifeste qui fait ensuite autorité (Phase 3 ne "
              "lancerait alors jamais `lxc-stop` sur ces modules). Relancez "
              "`scan` en root (sudo).", file=sys.stderr)
        return 1

    rc, out = _run(["lxc-ls", "-1"])
    # Même raisonnement que ci-dessus pour list-unit-files : rc=None ou
    # rc!=0 est indéterminé, jamais silencieusement traité comme "aucun
    # conteneur". La conséquence d'un mauvais repli ici est sévère (tous les
    # modules LXC dérivés en "native") : on abandonne plutôt que d'écrire.
    if rc != 0:
        print(f"⚠️  lxc-ls a échoué (rc={rc!r}) — impossible de déterminer "
              "quels modules tournent en conteneur LXC. Continuer "
              "dériverait tous les modules LXC en runtime=\"native\" dans un "
              "manifeste qui fait ensuite autorité (Phase 3 ne lancerait "
              "alors jamais `lxc-stop`). Corrigez lxc-ls (paquet lxc "
              "installé ? PATH ?) puis relancez `scan`.", file=sys.stderr)
        return 1
    lxc_names = {n.strip() for n in out.splitlines() if n.strip()}
    # load_routes() renvoie None quand le fichier de routes existe mais est
    # illisible/corrompu (indéterminable, distinct de "aucune route" = set()).
    # discover() attend un set() ferme (voir scan._route_for) donc on retombe
    # sur "aucune route connue" pour ne pas planter — MAIS ce repli fait
    # dériver `exposure` vers le bas (public -> lan/internal) pour tout module
    # routé, silencieusement, et scan n'écrase pas sans --force : la valeur
    # dégradée resterait autoritaire. On prévient donc l'opérateur sur stderr
    # dans ce seul cas (fichier présent mais illisible), jamais quand le
    # fichier est simplement absent (cas normal, routes = set()).
    routes = load_routes()
    if routes is None:
        print("⚠️  fichier de routes WAF illisible/corrompu — exposure peut être "
              "sous-évaluée pour les modules routés (public -> lan/internal). "
              "Corrigez le fichier de routes puis relancez `scan --force`.",
              file=sys.stderr)
        routes = set()
    manifests = discover(units=units, lxc_names=lxc_names, routes=routes)
    written = write_drafts(manifests, mod_dir, force=args.force)
    skipped = len(manifests) - len(written)
    print(f"{len(manifests)} module(s) découvert(s) — {len(written)} manifeste(s) écrit(s), "
          f"{skipped} conservé(s) (déjà présents ; --force pour écraser).")
    return 0


def _run(argv: list[str]) -> tuple[int | None, str]:
    """rc=None signale que la commande n'a PAS pu s'exécuter (OSError, timeout) —
    à distinguer d'un rc non-nul qui est une réponse authentique de la commande.
    Même contrat que observe._run_cmd : un (1, "") fabriqué ici serait
    indistinguable d'une vraie réponse "non" de la commande (voir _cmd_scan,
    qui a besoin de cette distinction pour ne pas écrire un manifeste faux)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


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

    sp = sub.add_parser("export", help="liste des paquets des modules actifs d'un profil")
    sp.add_argument("profile", help="nom du profil à exporter")
    sp.add_argument("--format", choices=["pkglist", "apt", "json"], default="pkglist")
    sp.set_defaults(func=_cmd_export)

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

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — profiler : dérive les manifestes du réel
CyberMind — https://cybermind.fr

On ne rédige pas 134 manifestes à la main : `scan` les dérive des units
systemd, des conteneurs LXC, des routes WAF et des menu.d/ existants, puis
l'opérateur corrige. Un manifeste corrigé fait ensuite autorité — d'où le
refus d'écraser sans --force.

Il n'existe pas d'écrivain TOML en stdlib (tomllib est en lecture seule) et le
schéma est petit et fixe : l'émetteur est écrit à la main plutôt que d'ajouter
une dépendance. Le test qui compte est l'aller-retour to_toml -> load_manifest.
"""
from __future__ import annotations

import json
from pathlib import Path

from .manifest import CATEGORIES, Manifest

MENU_DIR = Path("/usr/share/secubox/menu.d")

# Le noyau protégé : éteindre l'un de ceux-là retire à l'utilisateur le moyen
# de rallumer quoi que ce soit. Le premier scan doit déjà les marquer.
PROTECTED_IDS = frozenset({"auth", "aggregator", "core", "nginx", "firewall", "profiles"})

UNIT_PREFIX = "secubox-"
UNIT_SUFFIX = ".service"


def _id_from_unit(unit: str) -> str:
    return unit[len(UNIT_PREFIX):-len(UNIT_SUFFIX)]


def _menu_index(menu_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(Path(menu_dir).glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(d, dict) and d.get("id"):
            out[d["id"]] = d
    return out


def _category(menu: dict | None) -> str:
    # menu.d porte des catégories UI qui ne sont pas la taxonomie de
    # déploiement ; on ne recopie que celles qui coïncident, sinon infra.
    cat = (menu or {}).get("category")
    return cat if cat in CATEGORIES else "infra"


def _route_for(mid: str, routes: set[str]) -> str | None:
    for r in sorted(routes):
        if r.split(".")[0] == mid:
            return r
    return None


def discover(*, units: list[str], lxc_names: set[str], routes: set[str],
             menu_dir: Path = MENU_DIR) -> list[Manifest]:
    """Dérive un manifeste par unit secubox-*.service."""
    menus = _menu_index(menu_dir)
    out: list[Manifest] = []
    for unit in sorted(units):
        if not (unit.startswith(UNIT_PREFIX) and unit.endswith(UNIT_SUFFIX)):
            continue
        mid = _id_from_unit(unit)
        menu = menus.get(mid)
        domain = _route_for(mid, routes)
        if domain:
            exposure = "public"
        elif menu:
            exposure = "lan"       # entrée de menu mais pas de route publique (ex. lyrion)
        else:
            exposure = "internal"
        out.append(Manifest(
            id=mid,
            category=_category(menu),
            runtime="lxc" if mid in lxc_names else "native",
            exposure=exposure,
            units=(unit,),
            lxc=mid if mid in lxc_names else None,
            portal_domain=domain,
            protected=mid in PROTECTED_IDS,
        ))
    return out


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_list(items) -> str:
    return "[" + ", ".join(_toml_str(str(i)) for i in items) + "]"


def to_toml(m: Manifest) -> str:
    """Émet un manifeste. Aller-retour garanti avec load_manifest."""
    lines = [
        "# SPDX-License-Identifier: LicenseRef-CMSD-1.0",
        "# Manifeste dérivé par `secubox-profilectl scan` — corrigez-le, il fera",
        "# ensuite autorité (scan n'écrase pas sans --force).",
        f"id        = {_toml_str(m.id)}",
        f"category  = {_toml_str(m.category)}",
        f"runtime   = {_toml_str(m.runtime)}",
        f"exposure  = {_toml_str(m.exposure)}",
        f"units     = {_toml_list(m.units)}",
    ]
    if m.lxc:
        lines.append(f"lxc       = {_toml_str(m.lxc)}")
    if m.portal_domain:
        lines.append(f"portal    = {{ domain = {_toml_str(m.portal_domain)} }}")
    lines.append(f"priority  = {m.priority}")
    lines.append(f"protected = {'true' if m.protected else 'false'}")
    if m.needs:
        lines.append(f"needs     = {_toml_list(m.needs)}")
    return "\n".join(lines) + "\n"


def write_drafts(manifests, out_dir: Path, *, force: bool = False) -> list[Path]:
    """Écrit les manifestes dérivés. N'écrase JAMAIS sans force : un manifeste
    corrigé à la main fait autorité sur une dérivation."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for m in manifests:
        p = out_dir / f"{m.id}.toml"
        if p.exists() and not force:
            continue
        p.write_text(to_toml(m), encoding="utf-8")
        written.append(p)
    return written

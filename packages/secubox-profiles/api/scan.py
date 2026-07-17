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

from .manifest import CATEGORIES, PROTECTED_IDS, Manifest

MENU_DIR = Path("/usr/share/secubox/menu.d")

# PROTECTED_IDS vit désormais dans api.manifest (c'est une propriété du
# schéma, appliquée aussi au chargement — voir load_manifest) : réimporté ici
# pour que discover() continue de marquer le premier scan sans changement de
# comportement.

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


# menu.d (voir CATEGORY_META de secubox-hub) porte une taxonomie UI —
# auth, wall, boot, mind, root, mesh — distincte de la taxonomie de
# déploiement (api.manifest.CATEGORIES). Les deux partagent le jeton
# "mesh", mais le "mesh" de menu.d est un fourre-tout UI, PAS la
# catégorie réseau/P2P de déploiement : PeerTube et Lyrion (media)
# déclarent tous deux category="mesh" dans leur menu.d/, et un simple
# `cat in CATEGORIES` les classerait à tort en "mesh" de déploiement,
# corrompant les statistiques par catégorie que cette fonctionnalité
# doit produire. On mappe donc explicitement, jeton par jeton — ne
# jamais laisser passer une chaîne menu.d seulement parce qu'elle est
# orthographiée comme une catégorie de déploiement.
#
# mesh -> infra plutôt que -> network : une catégorie fausse mais valide
# est pire qu'une catégorie neutre, car elle a l'air d'une décision
# prise alors que ce n'en est pas une, et ne sera pas relue par
# l'opérateur. "infra" est le choix neutre, à corriger à la main.
MENU_CATEGORY_MAP: dict[str, str] = {
    "auth": "security",
    "wall": "security",
    "boot": "infra",
    "mind": "media",
    "root": "infra",
    "mesh": "infra",
}


def _category(menu: dict | None) -> str:
    cat = MENU_CATEGORY_MAP.get((menu or {}).get("category"), "infra")
    assert cat in CATEGORIES  # invariant : ne jamais émettre hors taxonomie
    return cat


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


_TOML_BASIC_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _toml_str(s: str) -> str:
    # Chaîne basique TOML : \\ et " en premier (évite un double-échappement),
    # puis les autres caractères de contrôle par leur échappement nommé,
    # et le reste par \\uXXXX — un \n ou un \t littéral non échappé produit
    # un fichier que tomllib refuse de relire ("Illegal character").
    out = []
    for ch in s:
        if ch in _TOML_BASIC_ESCAPES:
            out.append(_TOML_BASIC_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


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

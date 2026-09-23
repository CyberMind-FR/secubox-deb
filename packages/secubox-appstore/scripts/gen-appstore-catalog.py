#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-appstore :: catalog generator.

Scan every module's debian/secubox.yaml in the monorepo and emit a flat
catalog.json (the App Store's "available" set). Run at package build time
from packages/secubox-appstore (siblings live at ../*/debian/secubox.yaml).
Dependency-free: parses the small flat manifests without PyYAML.
"""
import json, sys, glob, os, re

def parse_manifest(path):
    m = {"depends": []}
    in_depends = False
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # top-level key: value (no leading space)
        mt = re.match(r"^([a-z_]+):\s*(.*)$", line)
        if mt:
            key, val = mt.group(1), mt.group(2).strip()
            in_depends = (key == "depends")
            if key in ("name", "category", "tier", "description") and val:
                m[key] = val.strip().strip('"').strip("'")
            continue
        # list item under depends:
        li = re.match(r"^\s+-\s+(.*)$", line)
        if li and in_depends:
            m["depends"].append(li.group(1).strip().strip('"').strip("'"))
    return m

def parse_groupes(path):
    """Lit groupes.yaml — une fonctionnalité, plusieurs paquets (#1323).

    Format plat, sans PyYAML : la chaîne de construction n'a pas de dépendance
    YAML et on ne va pas en ajouter une pour sept blocs de cinq lignes.
    """
    groupes, cur = [], None
    if not os.path.exists(path):
        return groupes
    for raw in open(path, encoding="utf-8", errors="replace"):
        ligne = raw.rstrip("\n")
        if not ligne.strip() or ligne.lstrip().startswith("#"):
            continue
        mt = re.match(r"^([a-z]+):\s*(.*)$", ligne)
        if mt:
            cle, val = mt.group(1), mt.group(2).strip().strip('"').strip("'")
            if cle == "groupe":
                cur = {"id": val, "label": val, "description": "", "modules": []}
                groupes.append(cur)
            elif cur is not None and cle in ("label", "description"):
                cur[cle] = val
            continue
        li = re.match(r"^\s+-\s+(.*)$", ligne)
        if li and cur is not None:
            cur["modules"].append(li.group(1).strip())
    return groupes


def main(out):
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    catalog = []
    for path in sorted(glob.glob(os.path.join(base, "*", "debian", "secubox.yaml"))):
        # skip generated build-tree copies (debian/<pkg>/...)
        if "/debian/" in path and path.count("/debian/") > 1:
            continue
        m = parse_manifest(path)
        if not m.get("name"):
            continue
        catalog.append({
            "name": m["name"],
            "category": m.get("category", "misc"),
            "tier": m.get("tier", "lite"),
            "description": m.get("description", ""),
            "depends": m.get("depends", []),
        })
    # de-dup by name (keep first)
    seen, uniq = set(), []
    for c in catalog:
        if c["name"] in seen:
            continue
        seen.add(c["name"]); uniq.append(c)
    # LES GROUPES SONT VALIDÉS CONTRE LE CATALOGUE. Un groupe qui cite un
    # module inexistant produirait un bouton « installer » condamné à échouer :
    # on préfère casser la CONSTRUCTION, où quelqu'un lit le message, plutôt
    # que l'interface, où l'utilisateur ne comprendra rien.
    connus = {c["name"] for c in uniq}
    groupes = parse_groupes(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "..", "groupes.yaml"))
    for g in groupes:
        inconnus = [m for m in g["modules"] if m not in connus]
        if inconnus:
            raise SystemExit(
                f"gen-appstore-catalog: groupe '{g['id']}' cite des modules "
                f"absents du catalogue : {', '.join(inconnus)}")

    data = {"version": 1, "modules": uniq, "count": len(uniq),
            "groupes": groupes}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"wrote {out}: {len(uniq)} modules, {len(groupes)} groupes")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "catalog.json")

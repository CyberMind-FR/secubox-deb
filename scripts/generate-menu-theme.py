#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Écrit la clé `theme` de chaque packages/*/menu.d/*.json, dérivée de arbre.yaml (#2050).

Le thème d'un paquet est la FONCTION qui contient le service qui le contient
(socle, reseau, bouclier, media…) ; pour un service rattaché directement à la
racine (hall, assistant), c'est le nom du service. `arbre.yaml` reste la source
unique ; `--check` (et le test de dérive) refuse un menu.d qui s'en écarte.

    scripts/generate-menu-theme.py          # écrit
    scripts/generate-menu-theme.py --check  # code 1 si dérive
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def _arbre():
    s = importlib.util.spec_from_file_location("gen_meta", RACINE / "packages/secubox-meta/gen-meta.py")
    g = importlib.util.module_from_spec(s)
    s.loader.exec_module(g)
    return g.lit_arbre()[0]


def _liens(n):
    return n.get("requiert", []) + n.get("recommande", []) + n.get("suggere", [])


def _court(meta: str) -> str:
    return re.sub(r"^secubox-(fonction|service)-", "", meta)


def theme_par_paquet() -> dict:
    noeuds = _arbre()
    par_nom = {n["meta"]: n for n in noeuds}
    service_vers_theme = {}
    for n in noeuds:
        if n["niveau"] == "fonction":
            for l in _liens(n):
                if l in par_nom and par_nom[l]["niveau"] == "service":
                    service_vers_theme.setdefault(l, _court(n["meta"]))
    for n in noeuds:  # services accrochés directement à la racine : leur propre nom
        if n["niveau"] == "service":
            service_vers_theme.setdefault(n["meta"], _court(n["meta"]))
    themes = {}
    for n in noeuds:
        if n["niveau"] == "service":
            for l in _liens(n):
                themes.setdefault(l, service_vers_theme[n["meta"]])
    return themes


def theme_de(paquet: str, themes: dict):
    return themes.get(paquet)


def _fichiers():
    return sorted(RACINE.glob("packages/*/menu.d/*.json"))


def _avec_theme(texte: str, theme: str) -> str:
    d = json.loads(texte)
    if d.get("theme") == theme:
        return texte
    if "theme" in d:
        return re.sub(r'("theme"\s*:\s*)"[^"]*"', rf'\1"{theme}"', texte, count=1)
    m = re.search(r'\n(\s*)"[^"]+"\s*:', texte)
    indent = m.group(1) if m else "  "
    corps = texte.rstrip()
    assert corps.endswith("}")
    return corps[:-1].rstrip() + f',\n{indent}"theme": "{theme}"\n}}\n'


def ecarts() -> list:
    themes = theme_par_paquet()
    mauvais = []
    for f in _fichiers():
        paquet = f.parts[-3]
        t = theme_de(paquet, themes)
        if t is None or _avec_theme(f.read_text(), t) != f.read_text():
            mauvais.append(str(f.relative_to(RACINE)))
    return mauvais


def main(argv) -> int:
    if "--check" in argv:
        e = ecarts()
        for x in e:
            print("dérive :", x)
        return 1 if e else 0
    themes = theme_par_paquet()
    ecrits = 0
    for f in _fichiers():
        t = theme_de(f.parts[-3], themes)
        if t is None:
            print("hors arbre :", f.parts[-3], file=sys.stderr)
            continue
        nouveau = _avec_theme(f.read_text(), t)
        if nouveau != f.read_text():
            json.loads(nouveau)
            f.write_text(nouveau)
            ecrits += 1
    print(f"{ecrits} menu.d mis à jour")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

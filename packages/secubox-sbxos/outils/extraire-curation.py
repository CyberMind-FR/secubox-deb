#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SBX OS :: EXTRAIT LA CURATION DU HALL (#1349).

POURQUOI UN GÉNÉRATEUR PLUTÔT QU'UNE COPIE. SBX OS est un CLONE du Hall : ce
qu'il montre doit être ce que le Hall montre, sans quoi ce sont deux bureaux
qui divergent lentement — et celui qu'on regarde le moins finit par mentir.

La curation du Hall (`const FEATURED`) vit dans son HTML, en JavaScript. On ne
la RECOPIE pas : on l'EXTRAIT mécaniquement, au moment de construire le paquet.
Le Hall reste la seule source ; SBX OS en reçoit une projection.

CE QU'ON N'EXTRAIT PAS. Les cartes de GROUPE (« securite », « contenu »…) n'ont
pas de service derrière elles : ce sont des agrégats propres au Hall, dont la
vue cumulée n'a pas de sens hors de son damier. On garde ce qui désigne un LIEU
réel — une adresse qu'on peut ouvrir.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

#: Champs qu'on sait lire dans une entrée FEATURED. Le reste — `h`, `carte`,
#: `micro` — décrit la façon dont le HALL encadre, et ne regarde pas SBX OS.
_CHAMPS = ("id", "label", "icon", "color", "url", "lan")


def _chemin(brut: str) -> str | None:
    """Page du Hall (hôte hall.<domaine>) d'une carte sans hôte propre (#2351). On préfère une VRAIE page
    (carte hors /cardlets/, sinon la page d'administration) ; une carte qui n'est qu'un widget du Hall
    n'est pas un lieu. Sans requête : seul le chemin est gardé."""
    cand = []
    c = re.search(r'\bcarte\s*:\s*"([^"]*)"', brut)
    if c and not c.group(1).startswith("/cardlets/"):
        cand.append(c.group(1))
    a = re.search(r'\badmin\s*:\s*"([^"]*)"', brut)
    if a:
        cand.append(a.group(1))
    for x in cand:
        x = x.split("?")[0]
        if re.fullmatch(r"/[a-z0-9][a-z0-9/_-]{0,60}/", x):
            return x
    return None


def extrait(html: str) -> list[dict]:
    bloc = re.search(r"const FEATURED\s*=\s*\[(.*?)\n\];", html, re.S)
    if not bloc:
        raise SystemExit("FEATURED introuvable — le Hall a changé de forme")

    sortie = []
    for brut in re.findall(r"\{id:\"[^\"]+\".*?\}", bloc.group(1), re.S):
        e = {}
        for champ in _CHAMPS:
            m = re.search(r'\b%s\s*:\s*"([^"]*)"' % champ, brut)
            if m:
                e[champ] = m.group(1)
            elif champ == "lan" and re.search(r"\blan\s*:\s*true", brut):
                e["lan"] = True
        # UNE CARTE SANS ADRESSE N'EST PAS UN LIEU. Les agrégats du Hall
        # (« securite », « contenu ») n'ouvrent rien par eux-mêmes.
        if e.get("id") and not e.get("url"):
            ch = _chemin(brut) if e["id"] != "sbxos" else None   # SBX OS ne se liste pas lui-même
            if ch:
                e["chemin"] = ch
        if e.get("id") and (e.get("url") or e.get("chemin")):
            sortie.append(e)
    return sortie


def main(argv: list[str] | None = None) -> int:
    import argparse
    # parents[2] = packages/ — le script vit dans packages/secubox-sbxos/outils/.
    racine = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description="Extrait la curation du Hall (const FEATURED) vers curation.json.")
    ap.add_argument("--source", type=Path, default=racine / "secubox-webos" / "www" / "hall" / "index.html")
    ap.add_argument("--sortie", type=Path,
                    default=Path(__file__).resolve().parents[1] / "www" / "mine" / "curation.json")
    a = ap.parse_args(argv)
    source, cible = a.source, a.sortie

    if not source.exists():
        print(f"source absente : {source}", file=sys.stderr)
        return 1

    lieux = extrait(source.read_text(encoding="utf-8"))
    doc = {
        "_pourquoi": "EXTRAIT du Hall (const FEATURED) par outils/extraire-curation.py. "
                     "Ne pas éditer à la main : la source est hall/index.html, et "
                     "toute correction faite ici serait perdue à la construction suivante.",
        "_source": "packages/secubox-webos/www/hall/index.html",
        "lieux": lieux,
    }
    cible.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{len(lieux)} lieux → {cible.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

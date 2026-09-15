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
        if e.get("id") and e.get("url"):
            sortie.append(e)
    return sortie


def main() -> int:
    # parents[2] = packages/ — le script vit dans packages/secubox-sbxos/outils/.
    racine = Path(__file__).resolve().parents[2]
    source = racine / "secubox-webos" / "www" / "hall" / "index.html"
    cible = Path(__file__).resolve().parents[1] / "www" / "mine" / "curation.json"

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

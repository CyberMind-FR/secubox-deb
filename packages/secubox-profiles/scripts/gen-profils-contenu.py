#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: gen-profils-contenu — le contenu des profils (minimal, lite, isp, full), LU des meta-paquets (#2819).

Usage : gen-profils-contenu.py <dossier packages> <espaces.json> <sortie.json>

Chaque profil est le meta-paquet `secubox-<profil>` : ses Depends sont la verite. Rien n'est saisi a la main : un module ajoute a un meta-paquet
apparait dans la page a la construction suivante. Un meta-paquet qui en inclut un autre (isp inclut lite, full inclut isp) est resolu en cumul.
Un module inconnu de espaces.json est range dans « autres » : jamais devine. Un meta-paquet illisible est une ERREUR, pas un profil vide."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

PROFILS = ["minimal", "lite", "isp", "full"]
LIBELLES = {"minimal": "Minimal", "lite": "Lite", "isp": "ISP", "full": "Full"}


class ProfilIncoherent(Exception):
    pass


def _depends(control: Path, paquet: str) -> list:
    try:
        txt = re.sub(r"^#.*\n", "", control.read_text(encoding="utf8"), flags=re.M)
    except OSError as e:
        raise ProfilIncoherent(f"{paquet} : control illisible ({e})")
    for blk in re.split(r"\n\n+", txt):
        if re.search(rf"^Package:\s*{re.escape(paquet)}\s*$", blk, re.M):
            d = " ".join(re.findall(r"^(?:Pre-)?Depends:((?:.*\n?(?: .*\n?)*))", blk, re.M)).replace("\n", " ")
            noms = []
            for alt in d.split(","):
                m = re.match(r"\s*(secubox-[a-z0-9.+-]+)", alt)      # la 1re alternative d'un « a | b »
                if m and m.group(1) not in noms:
                    noms.append(m.group(1))
            return noms
    raise ProfilIncoherent(f"{paquet} : paragraphe Package introuvable")


def _version(changelog: Path) -> str:
    try:
        m = re.match(r"^\S+ \(([^)]+)\)", changelog.read_text(encoding="utf8"))
    except OSError:
        return ""
    return m.group(1) if m else ""


def _espace(paquet: str, table: dict) -> str:
    mid = paquet.removeprefix("secubox-")
    for cand in (mid, re.sub(r"-ng$", "", mid)):
        if cand in table:
            return table[cand].get("espace") or "autres"
    return "autres"


def construire(packages: Path, espaces_json: Path) -> dict:
    packages = Path(packages)
    esp = json.loads(Path(espaces_json).read_text(encoding="utf8"))
    table = esp.get("modules", {})
    metas = {f"secubox-{p}" for p in PROFILS}
    brut = {}
    for p in PROFILS:
        nom = f"secubox-{p}"
        brut[p] = _depends(packages / nom / "debian" / "control", nom)

    def effectifs(p, vus=()):
        if p in vus:
            raise ProfilIncoherent(f"cycle entre profils : {p}")
        out = [x for x in brut[p] if x not in metas]
        for x in brut[p]:
            if x in metas:
                for y in effectifs(x.removeprefix("secubox-"), vus + (p,)):
                    if y not in out:
                        out.append(y)
        return out

    profils = []
    for p in PROFILS:
        inclus = [x.removeprefix("secubox-") for x in brut[p] if x in metas]
        directs = [x for x in brut[p] if x not in metas]
        modules = effectifs(p)
        base = set(effectifs(inclus[0])) if inclus else set()
        fiche = lambda l: [{"paquet": x, "espace": _espace(x, table)} for x in l]     # noqa: E731
        profils.append({"id": p, "label": LIBELLES[p], "meta": f"secubox-{p}", "version": _version(packages / f"secubox-{p}" / "debian" / "changelog"),
                        "inclut": inclus[0] if inclus else None, "directs": fiche(directs), "modules": fiche(modules),
                        "ajoutes": fiche([x for x in modules if x not in base]), "total": len(modules)})
    mini = {m["paquet"] for m in next(x for x in profils if x["id"] == "minimal")["modules"]}
    autres = {}
    for x in profils:
        if x["id"] != "minimal":
            for m in x["modules"]:
                if m["paquet"] not in mini:
                    autres.setdefault(m["paquet"], m)
    return {"version": 1, "profils": profils,
            "espaces": [{"id": e["id"], "nom": e.get("nom", e["id"]), "icone": e.get("icone", ""), "ordre": e.get("ordre", 99)} for e in esp.get("espaces", [])] + [{"id": "autres", "nom": "Autres", "icone": "", "ordre": 99}],
            "absents_de_minimal": sorted(autres.values(), key=lambda m: m["paquet"])}


def main(argv=None) -> int:
    a = sys.argv[1:] if argv is None else argv
    if len(a) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        d = construire(Path(a[0]), Path(a[1]))
    except (ProfilIncoherent, OSError, ValueError) as e:
        print(f"[profils] ECHEC : {e}", file=sys.stderr)
        return 1
    sortie = Path(a[2])
    sortie.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=sortie.parent, prefix=".profils-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, sortie)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(f"[profils] {len(d['profils'])} profils, {len(d['absents_de_minimal'])} modules absents de minimal -> {sortie}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

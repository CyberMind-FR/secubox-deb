#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Découpe WIP.md / HISTORY.md / TODO.md par mois, SANS perte (#1863).

Usage : decoupe.py <ref-git> [--garde-actif TODO=2026-09-01]
Lit `.claude/<FICHIER>.md` à <ref-git>, coupe aux titres `## ` (hors blocs de
code), range les sections par mois (date du titre ; « sans-date » sinon) dans
`.claude/archive/<FICHIER>/<AAAA-MM>.md`, et écrit `manifest.json` : de quoi
reconstituer l'original à l'octet (voir `reassembler.py`).
Les sections « gardées actives » ne sont PAS archivées : le manifeste les note
avec leur empreinte, pour une vérification au commit de découpe."""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
ARCH = RACINE / ".claude" / "archive"
DATE = re.compile(r"(20\d\d)-(\d\d)-\d\d")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def lit(ref: str, nom: str) -> bytes:
    return subprocess.run(["git", "show", f"{ref}:.claude/{nom}.md"], check=True, capture_output=True,
                          cwd=RACINE).stdout


def sections(brut: bytes):
    """(entête, [(titre, lignes_bytes)…]) — coupe aux `## ` hors blocs ```."""
    lignes = brut.splitlines(keepends=True)
    dans_code, coupes = False, []
    for i, l in enumerate(lignes):
        s = l.lstrip()
        if s.startswith(b"```") or s.startswith(b"~~~"):
            dans_code = not dans_code
        if not dans_code and l.startswith(b"## "):
            coupes.append(i)
    if not coupes:
        return lignes, []
    entete = lignes[:coupes[0]]
    out = []
    for a, b in zip(coupes, coupes[1:] + [len(lignes)]):
        out.append((lignes[a].decode("utf8", "replace").strip(), lignes[a:b]))
    return entete, out


def mois_de(titre: str):
    m = DATE.search(titre)
    return f"{m.group(1)}-{m.group(2)}" if m else "sans-date"


def date_de(titre: str):
    m = DATE.search(titre)
    return m.group(0) if m else None


def main():
    ref = sys.argv[1]
    garde = {}
    if "--garde-actif" in sys.argv:
        for kv in sys.argv[sys.argv.index("--garde-actif") + 1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                garde[k] = v
    manifeste = {"ref": subprocess.run(["git", "rev-parse", ref], capture_output=True, text=True,
                                       cwd=RACINE).stdout.strip(), "fichiers": {}}
    for nom in ("WIP", "HISTORY", "TODO"):
        brut = lit(ref, nom)
        entete, secs = sections(brut)
        seuil = garde.get(nom)
        par_mois, desc = {}, []
        for idx, (titre, lg) in enumerate(secs):
            d = date_de(titre)
            actif = bool(seuil and d and d >= seuil)
            mois = mois_de(titre)
            desc.append({"idx": idx, "titre": titre[:140], "mois": mois, "actif": actif,
                         "lignes": len(lg), "sha256": sha(b"".join(lg))})
            if not actif:
                par_mois.setdefault(mois, []).append((idx, lg))
        dossier = ARCH / nom
        dossier.mkdir(parents=True, exist_ok=True)
        (dossier / "_entete.md").write_bytes(b"".join(entete))
        for mois, items in par_mois.items():
            (dossier / f"{mois}.md").write_bytes(b"".join(b"".join(lg) for _, lg in items))
        fich = {m: {"sections": [i for i, _ in it],
                    "lignes": sum(len(lg) for _, lg in it),
                    "sha256": sha(b"".join(b"".join(lg) for _, lg in it))} for m, it in sorted(par_mois.items())}
        manifeste["fichiers"][nom] = {"original_sha256": sha(brut), "original_lignes": len(brut.splitlines()),
                                      "original_octets": len(brut), "entete_lignes": len(entete),
                                      "entete_sha256": sha(b"".join(entete)),
                                      "archives": fich, "sections": desc}
    (ARCH / "manifest.json").write_text(json.dumps(manifeste, ensure_ascii=False, indent=1) + "\n", encoding="utf8")


if __name__ == "__main__":
    main()

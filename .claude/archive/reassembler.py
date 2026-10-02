#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Preuve de zéro perte (#1863) : reconstitue WIP/HISTORY/TODO d'origine depuis
l'archive et compare l'empreinte SHA-256 à celle du fichier d'origine.

Usage : reassembler.py [--actif-ref <ref-git>]
  Les sections « actives » (TODO) viennent de `.claude/TODO.md` à <ref-git>
  (le commit de découpe) ; sans --actif-ref, du fichier courant.
Code de sortie 0 = identique à l'octet, 1 = écart."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
ARCH = RACINE / ".claude" / "archive"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def decoupe(brut: bytes):
    lignes = brut.splitlines(keepends=True)
    dans_code, coupes = False, []
    for i, l in enumerate(lignes):
        s = l.lstrip()
        if s.startswith(b"```") or s.startswith(b"~~~"):
            dans_code = not dans_code
        if not dans_code and l.startswith(b"## "):
            coupes.append(i)
    return [lignes[a:b] for a, b in zip(coupes, coupes[1:] + [len(lignes)])] if coupes else []


def main() -> int:
    ref = sys.argv[sys.argv.index("--actif-ref") + 1] if "--actif-ref" in sys.argv else None
    m = json.loads((ARCH / "manifest.json").read_text(encoding="utf8"))
    code = 0
    for nom, f in m["fichiers"].items():
        par_idx = {}
        for mois, a in f["archives"].items():
            secs = decoupe((ARCH / nom / f"{mois}.md").read_bytes())
            assert len(secs) == len(a["sections"]), (nom, mois)
            for i, lg in zip(a["sections"], secs):
                par_idx[i] = b"".join(lg)
        actifs = [s for s in f["sections"] if s["actif"]]
        if actifs:
            brut = (subprocess.run(["git", "show", f"{ref}:.claude/{nom}.md"], check=True, capture_output=True,
                                   cwd=RACINE).stdout if ref else (RACINE / ".claude" / f"{nom}.md").read_bytes())
            # les sections actives sont reconnues par leur empreinte, dans l'ordre du fichier actif
            vues = {sha(b"".join(lg)): b"".join(lg) for lg in decoupe(brut)}
            for s in actifs:
                par_idx[s["idx"]] = vues.get(s["sha256"], b"")
        entete = (ARCH / nom / "_entete.md").read_bytes()
        total = entete + b"".join(par_idx.get(i, b"") for i in range(len(f["sections"])))
        ok = sha(total) == f["original_sha256"]
        code |= 0 if ok else 1
        print(f"{nom:8s} {'IDENTIQUE' if ok else 'ÉCART   '} {len(total):>8d} octets  sha256={sha(total)[:16]}…"
              f"  (original {f['original_octets']} octets, {f['original_lignes']} lignes)")
    return code


if __name__ == "__main__":
    sys.exit(main())

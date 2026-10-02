#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Preuve de zéro perte (#1863) : recompose l'ancien CLAUDE.md racine depuis les
fichiers de `.claude/reference/` et compare son SHA-256 à celui de l'original."""
import hashlib
import json
import sys
from pathlib import Path

D = Path(__file__).resolve().parent
m = json.loads((D / "_origine-CLAUDE.json").read_text(encoding="utf8"))
en_tete_long = None
par = {}
for fic in {o["fichier"] for o in m["ordre"]}:
    brut = (D / fic).read_bytes()
    corps = brut[brut.index(b"-->\n\n") + 5:]           # retire le bandeau SPDX posé à l'extraction
    lignes, dans, coupes = corps.splitlines(keepends=True), False, []
    for i, l in enumerate(lignes):
        if l.lstrip().startswith(b"```"):
            dans = not dans
        if not dans and l.startswith(b"## "):
            coupes.append(i)
    par[fic] = [b"".join(lignes[a:b]) for a, b in zip(coupes, coupes[1:] + [len(lignes)])]
total = m["entete"].encode()
for o in m["ordre"]:
    total += par[o["fichier"]].pop(0)
ok = hashlib.sha256(total).hexdigest() == m["sha256"]
print("CLAUDE.md d'origine", "IDENTIQUE" if ok else "ÉCART", len(total), "octets, sha256", hashlib.sha256(total).hexdigest()[:16] + "…")
sys.exit(0 if ok else 1)

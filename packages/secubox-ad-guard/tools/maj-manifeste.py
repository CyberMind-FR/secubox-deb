#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recalcule lists/MANIFEST.json (empreintes des listes livrées) après une modification volontaire. Refuse une liste invalide."""
import hashlib
import json
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI))
sys.path.append("/usr/lib/secubox/ad-guard")          # paquet installé : la bibliothèque est sous /usr/lib
from api import dnstv  # noqa: E402

man = {}
for cat in dnstv.CATEGORIES:
    f = ICI / "lists" / f"{cat}.txt"
    if cat == "custom":
        continue
    _, mauvaises, version = dnstv.lire_liste(f)
    if mauvaises:
        sys.exit("liste invalide : " + "; ".join(mauvaises))
    man[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
man["services.txt"] = hashlib.sha256((ICI / "lists" / "services.txt").read_bytes()).hexdigest()
(ICI / "lists" / "MANIFEST.json").write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
print("MANIFEST.json mis à jour :", ", ".join(sorted(man)))

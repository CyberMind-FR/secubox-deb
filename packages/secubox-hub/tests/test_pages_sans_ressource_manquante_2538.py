# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2538 — aucune page du hub ne lie une feuille ou un script LOCAL qui n'existe pas.

La Vue d'ensemble Aurora avait supprimé /apercu/apercu.css et apercu.js ; /espace/ et /appareil/ continuaient de les lier : deux pages sans
feuille de style, que rien ne signalait."""
import re
from pathlib import Path

WWW = Path(__file__).resolve().parents[1] / "www"
LIEN = re.compile(r'<(?:link|script)\b[^>]*?(?:href|src)="([^"#?]+)', re.I)


def _manquants():
    out = []
    for page in sorted(WWW.glob("*/index.html")):
        texte = re.sub(r"<!--.*?-->", "", page.read_text(encoding="utf-8", errors="replace"), flags=re.S)
        for ref in LIEN.findall(texte):
            if re.match(r"^(?:[a-z][a-z0-9+.-]*:|//|data:)", ref, re.I) or "${" in ref or ref.startswith("/api/"):
                continue
            cible = WWW / ref.lstrip("/") if ref.startswith("/") else page.parent / ref
            if not cible.is_file():
                out.append(f"{page.relative_to(WWW)} -> {ref}")
    return out


def test_aucune_ressource_locale_manquante():
    assert _manquants() == []

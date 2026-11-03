# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3418 : aucun proxy_pass vers un nom d'hôte externe écrit en dur dans les fragments nginx du dépôt.

nginx résout un tel nom AU CHARGEMENT : sans DNS au démarrage (live, box mobile, hors ligne), il refuse de démarrer
et toute l'interface disparaît (constat VM Alpha 20 : « host not found in upstream fonts.googleapis.com »).
Le nom doit passer par une variable + `resolver`, résolu à la requête."""
import re
from pathlib import Path

DEPOT = Path(__file__).resolve().parents[3]
LITTERAL = re.compile(r"^\s*proxy_pass\s+https?://([A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,})", re.M)


def test_aucun_nom_externe_litteral_dans_proxy_pass():
    fautifs = []
    for f in DEPOT.glob("packages/*/nginx/**/*.conf"):
        if "/debian/" in str(f):
            continue
        for m in LITTERAL.finditer(f.read_text(errors="replace")):
            if m.group(1) not in ("localhost",):
                fautifs.append(f"{f.relative_to(DEPOT)} : {m.group(1)}")
    assert not fautifs, fautifs


def test_le_snippet_des_polices_resout_a_la_requete():
    t = (DEPOT / "packages/secubox-hub/nginx/snippets/secubox-fonts.conf").read_text()
    assert t.count("resolver ") == 2 and "proxy_pass https://$sbx_fonts_css;" in t and "proxy_pass https://$sbx_fonts_s;" in t

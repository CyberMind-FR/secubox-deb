# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3258 (étape 0) — libellés des profils de l'atelier Auto-Load à jour.

« Minimal — DPI, … » est faux depuis #3218/#3260 : ni DPI ni toolbox dans minimal et lite. « ISP — protection +
hébergement » contredisait la décision du 2026-10-29 : isp = fournisseur d'accès local avec DPI, NetFlow et cabine
numérique (profils/isp.toml de secubox-profiles)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
PAQUETS = PKG.parent
PAGE = (PKG / "www" / "autoload" / "index.html").read_text(encoding="utf-8")


def _option(valeur: str) -> str:
    m = re.search(rf'<select id="fProfil">.*?<option value="{valeur}">([^<]*)</option>', PAGE, re.S)
    assert m, valeur
    return m.group(1)


def test_le_libelle_minimal_ne_promet_plus_le_dpi():
    assert _option("minimal") == "Minimal — dns-guard, ad-guard, NAC, Freebox, maillage"


def test_le_libelle_isp_suit_la_decision_et_le_profil_d_activation():
    assert _option("isp") == "ISP — protection + DPI, NetFlow, cabine numérique"
    isp = (PAQUETS / "secubox-profiles" / "profiles" / "isp.toml").read_text(encoding="utf-8")
    assert re.search(r'^label = "ISP — protection \+ DPI, NetFlow, cabine numérique"$', isp, re.M)


def test_plus_aucun_libelle_minimal_dpi_dans_le_depot():
    motif = re.compile(r"Minimal\s*[—–-]\s*DPI|profil minimal\s*:\s*DPI")
    fautifs = []
    for p in PAQUETS.glob("*/**/*"):
        if not p.is_file() or "/tests/" in p.as_posix() or p.suffix not in {".html", ".js", ".yaml", ".yml", ".py", ".toml", ".json"}:
            continue
        try:
            if motif.search(p.read_text(encoding="utf-8")):
                fautifs.append(str(p.relative_to(PAQUETS)))
        except (UnicodeDecodeError, OSError):
            continue
    assert not fautifs, fautifs

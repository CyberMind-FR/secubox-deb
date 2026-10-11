# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2349 — un lien vers un service de la box ne passe pas par le surf (le relais le refuse : garde SSRF)."""
import pathlib

HALL = (pathlib.Path(__file__).resolve().parents[1] / "www/hall/index.html").read_text()


def _corps(nom):
    i = HALL.index("function " + nom)
    return HALL[i:i + 2600]


def test_ouvre_surf_detourne_les_hotes_de_la_box():
    c = _corps("ouvreSurf")
    assert c.index("SBX_DOMAINE") < c.index("surf-ov-f"), "la garde doit précéder l'ouverture du surf"
    assert "ouvreHote(" in c and "window.open(" in c


def test_ouvre_hote_connait_le_domaine_reel():
    assert "SBX_DOMAINE.hote(x.url) === hote" in _corps("ouvreHote")

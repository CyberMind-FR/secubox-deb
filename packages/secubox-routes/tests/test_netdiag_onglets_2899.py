# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2899 — netdiag absorbe Routes et SOC Reseau en onglets ; iperf3 est integre ; minimal l'embarque."""
import re
import tomllib
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
PAGE = (ICI / "composants/netdiag/www/netdiag/index.html").read_text()
CONTROL = (ICI / "debian/control").read_text()
PAQUETS = ICI.parent


def test_onglets_natifs_depuis_2915():
    """#2899 les avait mis en iframes ; #2915 les porte en code natif (voir test_netdiag_natif_2915.py)."""
    assert "<iframe" not in PAGE
    assert 'data-t="direct"' in PAGE and 'id="rtForm"' in PAGE


def test_l_entree_de_menu_routes_est_retiree():
    assert not (ICI / "menu.d/907-routes.json").exists()


def test_iperf3_est_integre_pas_seulement_recommande():
    dep = CONTROL.split("Depends:", 1)[1].split("Recommends:", 1)[0]
    assert "iperf3" in dep


def test_routes_et_netdiag_quittent_minimal_3218():
    """#2899 les embarquait dans minimal ; le banc de l'ESPRESSObin de 1 Go (#3218) en a fait un surplus (39 Mo chacun)."""
    ctrl = (PAQUETS / "secubox-minimal/debian/control").read_text()
    depends, conflicts = ctrl.split("Package: secubox-minimal", 1)[1].split("Conflicts:", 1)
    assert "secubox-routes" not in re.sub(r"^#.*$", "", depends, flags=re.M)
    assert "secubox-routes" in conflicts.split("Description:")[0]
    on = tomllib.loads((PAQUETS / "secubox-profiles/profiles/minimal.toml").read_text())["on"]
    assert "netdiag" not in on and "routes" not in on

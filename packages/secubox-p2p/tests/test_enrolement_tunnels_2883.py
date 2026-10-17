# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""L'ecouteur d'enrolement 7331 admet les tunnels d'administration (#2883).

Une box rattachee par wg-autoload (10.64.0.0/16) ou wg-mesh (10.10.0.0/24)
recevait 403 : seul $lan_client passait. Le jeton reste valide par le module.
"""
import re
from pathlib import Path

CONF = (Path(__file__).resolve().parents[1] / "nginx" / "p2p-masterlink.conf").read_text()


def test_les_deux_tunnels_sont_admis():
    assert re.search(r"10\.64\.0\.0/16\s+1", CONF)
    assert re.search(r"10\.10\.0\.0/24\s+1", CONF)


def test_la_garde_n_est_plus_lan_seul():
    assert "if ($lan_client = 0)" not in CONF
    assert "if ($p2p_enrol_ok = 0) { return 403; }" in CONF


def test_le_lan_reste_admis():
    assert "$lan_client$p2p_enrol_tunnel" in CONF


def test_pas_d_ouverture_generale():
    assert not re.search(r"0\.0\.0\.0/0\s+1", CONF)

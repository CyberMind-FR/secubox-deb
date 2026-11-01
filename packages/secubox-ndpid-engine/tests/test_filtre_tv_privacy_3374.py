# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SBX TV Privacy lot 4 (#3374) : filtre de capture par MAC (posé par root via ad-guard) et garde CPU de nDPId."""
from pathlib import Path

from test_interface_2740 import banc  # noqa: F401  (fixture)

PKG = Path(__file__).resolve().parents[1]


def test_filtre_par_mac_transmis_a_nDPId(banc):  # noqa: F811
    carte, lance = banc
    carte("eth0")
    r, args = lance("eth0", filtre="ether host aa:bb:cc:00:00:01 or ether host aa:bb:cc:00:00:02")
    assert r.returncode == 0
    assert args == "-l -i eth0 -B ether host aa:bb:cc:00:00:01 or ether host aa:bb:cc:00:00:02 -c /run/c.sock -u u -g g"


def test_filtre_hors_forme_ignore(banc):  # noqa: F811
    carte, lance = banc
    carte("eth0")
    r, args = lance("eth0", filtre="tcp; rm -rf /")
    assert args == "-l -i eth0 -c /run/c.sock -u u -g g" and "filtre" in r.stdout + r.stderr


def test_unite_bridee_et_lit_le_filtre_d_ad_guard():
    u = (PKG / "systemd" / "secubox-ndpid-engine.service").read_text()
    assert "EnvironmentFile=-/etc/secubox/ndpid-engine.d/tv-privacy.env" in u
    assert "CPUQuota=25%" in u and "Nice=10" in u

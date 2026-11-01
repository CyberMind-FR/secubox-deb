# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SBX TV Privacy lot 4 (#3374) : garde CPU de nDPId, capture COMPLÈTE conservée (aucun filtre de capture : Hall et /ndpid/)."""
from pathlib import Path

from test_interface_2740 import banc  # noqa: F401  (fixture)

PKG = Path(__file__).resolve().parents[1]


def test_aucun_filtre_de_capture_meme_si_une_variable_traine(banc):  # noqa: F811
    carte, lance = banc
    carte("eth0")
    r, args = lance("eth0", filtre="ether host aa:bb:cc:00:00:01")
    assert args == "-l -i eth0 -c /run/c.sock -u u -g g"


def test_unite_bridee_sans_filtre():
    u = (PKG / "systemd" / "secubox-ndpid-engine.service").read_text()
    assert "CPUQuota=40%" in u and "Nice=10" in u
    assert "tv-privacy.env" not in u and "-B" not in (PKG / "sbin" / "secubox-ndpid-engine-run").read_text()

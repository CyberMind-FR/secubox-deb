# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3833 : plus aucune source cyberfeed sur l'URL abuse.ch retirée (410 Gone)."""
from pathlib import Path


def test_pas_d_url_urlhaus_morte():
    src = (Path(__file__).resolve().parents[1] / "composants" / "cyberfeed" / "api" / "main.py").read_text(encoding="utf-8")
    assert "urlhaus.abuse.ch/downloads/hostfile" not in src, "source URLhaus morte (410) encore référencée"
    assert "malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt" in src

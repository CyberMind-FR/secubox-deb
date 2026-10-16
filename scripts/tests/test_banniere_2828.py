# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2828 — la banniere de connexion annonce l'adresse que l'image sert vraiment : https://<IP>/ (443), pas le port 9443 (copie de l'image Raspberry Pi, ferme sur l'ESPRESSObin)."""
from pathlib import Path

BUILD = (Path(__file__).resolve().parents[2] / "image" / "build-image.sh").read_text()


def test_aucun_port_9443_annonce():
    assert ":9443" not in BUILD


def test_la_banniere_donne_l_adresse_https_sans_port():
    assert "https://<IP>/" in BUILD

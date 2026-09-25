# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""La maquette de l'Identity Manager (#1405) : une référence, deux copies."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[4]
DOC = RACINE / "docs" / "design" / "sbxos-identite-maquette.html"
SERVIE = RACINE / "packages" / "secubox-sbxid" / "acces" / "www" / "acces" / "maquette.html"


def test_les_deux_copies_sont_identiques():
    assert DOC.read_text() == SERVIE.read_text(), "modifier docs/design puis recopier"


def test_aucun_appel_reseau():
    """Données d'exemple seulement : une maquette ne parle à aucune API."""
    s = SERVIE.read_text()
    assert not re.search(r"\bfetch\(|XMLHttpRequest|new WebSocket|sendBeacon", s)


def test_la_frontiere_systeme_est_montree():
    s = SERVIE.read_text()
    assert "ssh" in s and "NOT GLOB" in s          # capacité système refusée
    assert "jamais migrés dans sbx_users" in s      # comptes système hors SBX OS

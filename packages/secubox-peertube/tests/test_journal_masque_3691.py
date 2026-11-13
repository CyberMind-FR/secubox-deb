# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3691 : socket.io de PeerTube passe le jeton d'accès dans l'URL ; le journal du site ne doit plus l'écrire en clair."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]


def test_journaux_du_site_au_format_masque():
    for rel in ("nginx/peertube.vhost.conf", "conf/peertube.nginx.conf"):
        for ligne in (PAQUET / rel).read_text().splitlines():
            m = re.match(r"\s*access_log\s+(\S+)(?:\s+(\S+?))?;", ligne)
            if m and m.group(1) != "off":
                assert m.group(2) in ("sbx_masque", "sbx_host"), f"{rel} : {ligne.strip()}"


def test_depend_du_core_qui_definit_le_format():
    assert "secubox-core (>= 1.8.25~)" in (PAQUET / "debian/control").read_text()

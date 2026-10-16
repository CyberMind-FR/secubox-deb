# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2836 — le controle de vie `/health` de nginx ne masque pas la page Sante `/health/`.

`location /health { return 200 ... }` est un PREFIXE : il captait aussi `/health/` (la page Sante livree par secubox-hub) et la box repondait
{"status":"ok"} (15 octets) au lieu de la page. Constate sur l'ESPRESSObin."""
import re
from pathlib import Path

CONF = (Path(__file__).resolve().parents[3] / "common" / "nginx" / "secubox.conf").read_text()


def test_aucun_location_health_en_prefixe():
    assert not re.search(r"location\s+/health\s*\{", CONF), "location /health { … } est un prefixe : il masque la page /health/"


def test_le_controle_de_vie_est_une_egalite_exacte_dans_les_deux_serveurs():
    assert len(re.findall(r"location\s*=\s*/health\s*\{", CONF)) == 2      # le serveur HTTPS et le repli HTTP


def test_le_controle_de_vie_garde_sa_reponse():
    bloc = re.search(r"location\s*=\s*/health\s*\{(.*?)\n    \}", CONF, re.S).group(1)
    assert 'return 200 \'{"status":"ok"}\'' in bloc

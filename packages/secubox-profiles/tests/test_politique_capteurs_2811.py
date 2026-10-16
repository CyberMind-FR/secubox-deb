# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2811 — un module que sbxmitm ALIMENTE par socket ne doit jamais dormir.

Le relais de sbxmitm (internal/relay) jette sans bruit l'evenement quand le socket n'existe pas. `cookies` etait `on-demand` : le sleeper l'endormait,
plus rien n'etait ecrit dans mitm-ingest.db (derniere ecriture le 12 septembre) et la page /cookies/ n'affichait que des metriques vides."""
import re
import tomllib
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
POLITIQUE = tomllib.loads((PKG / "policy" / "lifecycle-defaults.toml").read_text())["lifecycle"]
RELAIS = (PKG.parent / "secubox-toolbox-ng" / "cmd" / "sbxmitm" / "relay.go").read_text()


def test_cookies_ne_dort_jamais():
    assert POLITIQUE["cookies"] == "always-on"


def test_les_cibles_de_socket_du_relais_ne_sont_pas_a_la_demande():
    """dpi.sock et cookies.sock sont des cibles du relais : leur module ne doit pas etre endormi."""
    sockets = dict(re.findall(r'(dpiSocket|cookiesSocket)\s*=\s*"/run/secubox/([a-z0-9-]+)\.sock"', RELAIS))
    assert set(sockets.values()) == {"dpi", "cookies"}
    for module in sockets.values():
        assert POLITIQUE.get(module) == "always-on", module

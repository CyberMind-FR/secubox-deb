# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2251 : dans un vhost, l'include du réveil (secubox-waking) précède celui des pages d'erreur (secubox-errorpages). Les deux déclarent
`error_page 502 503 504` au même niveau et nginx retient la PREMIÈRE : sinon la page « 504 — Délai dépassé » masque le réveil, le waker n'est
jamais appelé et un conteneur à la demande arrêté ne se réveille pas (photoprism, peertube, radio, podcaster)."""
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[2] / "packages"


def vhosts():
    for f in PACKAGES.rglob("*.conf"):
        p = f.relative_to(PACKAGES).parts
        if ("debian" in p[1:] and f.parent.name != "debian") or set(p) & {"_gocache", "_gopath", "vendor", "node_modules"}:
            continue
        try:
            t = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        code = [l for l in t.splitlines() if not l.lstrip().startswith("#")]
        w = [i for i, l in enumerate(code) if "snippets/secubox-waking.conf" in l]
        e = [i for i, l in enumerate(code) if "snippets/secubox-errorpages.conf" in l]
        if w and e:
            yield f.relative_to(PACKAGES), w[0], e[0]


def test_le_reveil_precede_les_pages_d_erreur_dans_tous_les_vhosts():
    mauvais = [str(f) for f, w, e in vhosts() if w > e]
    assert not mauvais, f"réveil masqué par les pages d'erreur : {mauvais}"


def test_la_garde_voit_bien_des_vhosts():
    assert {f.name for f, _, _ in vhosts()} >= {"photoprism.gk2.conf", "peertube.gk2.conf"}

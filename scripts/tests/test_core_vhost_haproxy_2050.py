# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2050 : le postinst de secubox-core ne ré-active pas la vhost nginx 80/443 sur une box derrière HAProxy.

Constaté sur gk3 (core 1.5.57) : le lien sites-enabled/secubox manquait, le postinst l'a recréé ; la vhost écoute
sur 80/443, HAProxy les tient, et `nginx reload` ne prenait plus aucun changement (bind() failed)."""
import re
from pathlib import Path

POSTINST = (Path(__file__).resolve().parents[2] / "packages/secubox-core/debian/postinst").read_text()


def test_le_lien_n_est_pas_cree_derriere_haproxy():
    cond = re.search(r"(?m)^\s*if \[ ! -e /etc/nginx/sites-enabled/secubox \].*$", POSTINST)
    assert cond, "condition de creation du lien introuvable"
    assert "_haproxy_devant" in cond.group(0), "la creation du lien doit etre gardee par la presence de HAProxy"


def test_la_garde_regarde_le_binaire_et_la_configuration():
    assert "/etc/haproxy/haproxy.cfg" in POSTINST and "command -v haproxy" in POSTINST

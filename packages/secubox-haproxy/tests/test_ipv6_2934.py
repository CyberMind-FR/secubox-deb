# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2934 — option `ipv6` de haproxy.toml : écouteurs IPv6 80 et 443, désactivés par défaut.

v6only (et non v4v6) : les écouteurs IPv4 existants restent strictement inchangés et aucune adresse IPv4 mappée
(::ffff:a.b.c.d) n'arrive au WAF."""
import re

from tests.test_ports_par_defaut_2526 import TOML_BOX_NEUVE, _generer


def test_par_defaut_aucun_ecouteur_ipv6(tmp_path):
    cfg = _generer(tmp_path, TOML_BOX_NEUVE)
    assert not re.search(r"^\s*bind :::", cfg, re.M)
    assert re.search(r"^\s*bind \*:443 ssl", cfg, re.M)


def test_ipv6_vrai_ajoute_80_et_443_en_v6only(tmp_path):
    cfg = _generer(tmp_path, 'ipv6 = true\n' + TOML_BOX_NEUVE)
    assert re.search(r"^\s*bind :::80 v6only\s*$", cfg, re.M)
    assert re.search(r"^\s*bind :::443 v6only ssl crt \S+", cfg, re.M)
    # les écouteurs IPv4 ne changent pas
    assert re.search(r"^\s*bind \*:80\s*$", cfg, re.M)
    assert re.search(r"^\s*bind \*:443 ssl crt \S+", cfg, re.M)
    assert not re.search(r"v4v6", cfg)


def test_ipv6_faux_ou_absent_ne_change_rien(tmp_path):
    cfg = _generer(tmp_path, 'ipv6 = false\n' + TOML_BOX_NEUVE)
    assert not re.search(r"^\s*bind :::", cfg, re.M)


def test_les_ports_personnalises_sont_repris_en_ipv6(tmp_path):
    cfg = _generer(tmp_path, 'ipv6 = true\nhttp_port = 8080\nhttps_port = 8443\n' + TOML_BOX_NEUVE)
    assert re.search(r"^\s*bind :::8080 v6only\s*$", cfg, re.M)
    assert re.search(r"^\s*bind :::8443 v6only ssl", cfg, re.M)

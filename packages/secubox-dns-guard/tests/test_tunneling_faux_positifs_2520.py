# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2520 — la détection de tunneling DNS ne doit pas lever d'alerte sur du trafic ordinaire.

Cas relevés dans les 2 728 domaines les plus demandés d'une box réelle : 443 faux « tunneling high » sur 452 alertes (regle base64 appliquee
a la concatenation de tous les sous-domaines)."""
import tempfile
from pathlib import Path

import pytest

import api.main as m


@pytest.fixture()
def garde():
    return m.DnsGuard(Path(tempfile.mkdtemp()))


LEGITIMES = [
    "firefox.settings.services.mozilla.com",
    "dualstack.guardian.map.fastly.net",
    "onedscolprdcus53.centralus.cloudapp.azure.com",
    "onedscolprdeus20.eastus.cloudapp.azure.com",
    "content-autofill.googleapis.com",
    "this-url-does-not-exist-8af2c188-e718-4edf-bf31-2a054794bde2.invalid",
    "detectportal.firefox.com",
    "safebrowsing.googleapis.com",
    "productionresultssa13.blob.core.windows.net",                  # mot + suffixe numerique court
    "5cu3d7b2bkcbscmomi6vkyzxbm.dwl.dnswl.org",                      # requetes DNSBL / DNSWL d'un serveur de courrier : label haché par conception
    "pc9tpea8zjk1asma1e9akxdhxhx34thw.email.rspamd.com",
    "211dddffb3c464dcb145630a7e5285f1b55ae190.ebl.msbl.org",
    "w2f3iozifbll3kkj7asbdhy0f.uribl.spameatingmonkey.net",
    "surf-bded8a3c6ae--1--1053047382554-us--central1-run-app.gk2.exemple.net",   # mots et nombres separes par des tirets
]

TUNNELS = [
    "dGhpcyBpcyBhIHRlc3Q9aGVsbG8gd29ybGQ4.exfil.example.com",         # base64 : lettres, chiffres, casse melangee
    "aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRhMTIz.evil.example.net",
    "4a6f686e20446f6520736563726574206461746120686572652e2e2e2e.t.example.org",  # hexadecimal long
    "x" * 55 + ".example.com",                                        # label > 50 (a faire tenir a la regle « long label »)
]


@pytest.mark.parametrize("domaine", LEGITIMES)
def test_trafic_ordinaire_sans_alerte_de_tunneling(garde, domaine):
    assert garde.detect_tunneling(domaine) is None


@pytest.mark.parametrize("domaine", TUNNELS)
def test_vrais_tunnels_toujours_detectes(garde, domaine):
    a = garde.detect_tunneling(domaine)
    assert a is not None and a.type == m.DetectionType.TUNNELING


def test_label_long_en_mots_separes_par_tirets_n_est_pas_du_tunneling(garde):
    assert garde.detect_tunneling("mise-a-jour-du-catalogue-des-extensions-de-securite-pour-le-navigateur.example.com") is None


def test_label_hexadecimal_de_63_caracteres_reste_critique(garde):
    a = garde.detect_tunneling("bc8260ec693127548e24db565e8baaf13a4e30acabd1cd1007f1f0f0a2793af.us-east-1.example.com")
    assert a is not None and a.severity == m.Severity.CRITICAL

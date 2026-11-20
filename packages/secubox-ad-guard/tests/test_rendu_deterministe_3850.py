# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3850 — le drop-in Unbound de TV Privacy est IDENTIQUE tant que l'état ne change pas, quel que soit l'ordre des
évasions et quarantaines dans l'état. Sur gk2 (20/11), deux vues `sbx-evasion-*` permutaient d'un passage à l'autre :
chaque réécriture relançait la compilation complète des listes DNS (~8 min de processeur) et unbound-checkconf."""
import itertools
import time

from api import dnstv

FIN = int(time.time()) + 3600
CLIENTS = [{"ip": "192.168.1.50", "nom": "tv-salon", "mode": "auto"}]
EVASIONS = [{"ip": "192.168.1.112", "mac": "aa:bb:cc:dd:ee:01", "noms": ["dns.google", "cloudflare-dns.com"]},
            {"ip": "2a01:e0a:dec:c4e0:61ad:5f59:9af6:f4b2", "mac": "aa:bb:cc:dd:ee:02", "noms": ["dns.quad9.net"]}]
QUARANTAINES = [{"ip": "192.168.1.77", "mac": "aa:bb:cc:dd:ee:03", "fin": FIN},
                {"ip": "192.168.1.78", "mac": "aa:bb:cc:dd:ee:04", "fin": FIN}]


def _rendu(evasions, quarantaines):
    etat = {"actif": True, "clients": CLIENTS, "evasions": evasions, "quarantaines": quarantaines}
    return dnstv.rendre_unbound(etat, {"ads.example.com": "advertising"}, None,
                                adresses_box=("192.168.1.200", None), maintenant=FIN - 60)


def test_ordre_des_evasions_et_quarantaines_sans_effet():
    rendus = {_rendu(list(e), list(q)) for e in itertools.permutations(EVASIONS)
              for q in itertools.permutations(QUARANTAINES)}
    assert len(rendus) == 1


def test_ordre_des_noms_refuses_sans_effet():
    a = _rendu([{**EVASIONS[0], "noms": ["dns.google", "cloudflare-dns.com"]}], [])
    b = _rendu([{**EVASIONS[0], "noms": ["cloudflare-dns.com", "dns.google"]}], [])
    assert a == b


def test_les_mesures_restent_rendues():
    out = _rendu(EVASIONS, QUARANTAINES)
    for ip in ("192.168.1.112/32", "192.168.1.77/32", "192.168.1.78/32", "2a01:e0a:dec:c4e0:61ad:5f59:9af6:f4b2/128"):
        assert f"access-control-view: {ip} sbx-" in out
    assert 'local-zone: "dns.google." always_refuse' in out
    assert out.count("sbx-quarantaine-") == 4      # 2 access-control-view + 2 name:

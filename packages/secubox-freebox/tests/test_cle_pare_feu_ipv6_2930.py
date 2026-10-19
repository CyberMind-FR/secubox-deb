# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2930 — le pare-feu IPv6 de la Freebox se lit et s'ecrit avec la VRAIE cle.

Sonde reelle (gk2, 2026-10-19) : connection/ipv6/config/ rend {ipv6_enabled, ipv6_prefix_firewall, ipv6ll, delegations}.
Le module utilisait « ipv6_firewall » : lecture None, ecriture sans effet. Les anciens firmwares gardent l'ancienne cle."""
import json

from tests.test_pare_feu_ecriture import _pret, ok


def test_ecriture_avec_la_cle_reelle_ipv6_prefix_firewall(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_enabled": True, "ipv6_prefix_firewall": True}),
                                       ok({"ipv6_prefix_firewall": False}), ok({"ipv6_prefix_firewall": False})])
    r = svc.regler_pare_feu_ipv6(False)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and json.loads(puts[0][3]) == {"ipv6_prefix_firewall": False}
    assert r["pare_feu_actif"] is False and r["change"] is True
    assert journal[0]["avant"] is True and journal[0]["apres"] is False


def test_ancienne_cle_toujours_acceptee(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_firewall": True}), ok({"ipv6_firewall": False}), ok({"ipv6_firewall": False})])
    svc.regler_pare_feu_ipv6(False)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert json.loads(puts[0][3]) == {"ipv6_firewall": False}


def test_deja_dans_l_etat_voulu_avec_la_cle_reelle(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_prefix_firewall": True})])
    assert svc.regler_pare_feu_ipv6(True)["change"] is False
    assert not [a for a in f.appels if a[0] == "PUT"]

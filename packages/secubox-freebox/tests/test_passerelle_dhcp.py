# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Bascule de la passerelle DHCP Freebox (#2940) : même charpente que regler_pare_feu_ipv6."""
from tests.test_pare_feu_ecriture import _pret, ok


def test_passerelle_ecrit_puis_relit_et_journalise(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"gateway": "192.168.1.254"}),
                                       ok({"gateway": "192.168.1.200"}), ok({"gateway": "192.168.1.200"})])
    r = svc.regler_passerelle_dhcp("192.168.1.200")
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("dhcp/config/")
    assert r["passerelle"] == "192.168.1.200" and r["change"] is True
    assert journal[0]["action"] == "passerelle_dhcp" and journal[0]["apres"] == "192.168.1.200"


def test_deja_dans_l_etat_voulu_n_ecrit_rien(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"gateway": "192.168.1.200"})])
    r = svc.regler_passerelle_dhcp("192.168.1.200")
    assert r["change"] is False and not [a for a in f.appels if a[0] == "PUT"]

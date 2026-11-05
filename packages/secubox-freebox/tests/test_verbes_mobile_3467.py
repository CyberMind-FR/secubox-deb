# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Verbes de la clé mobile (#3467) : une réponse anormale est une erreur, une écriture est relue."""
import pytest

from api import client as C
from tests.test_pare_feu_ecriture import _pret, ok


def test_lire_dns_refuse_une_reponse_anormale(tmp_path):
    svc, _, _ = _pret(tmp_path, [ok({"dns": None})])
    with pytest.raises(C.ErreurFreebox):
        svc.lire_dns()


def test_regler_dns_ecrit_six_cases_et_relit(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"dns": ["1.1.1.1"]}), ok({"dns": ["192.168.1.50"]}), ok({"dns": ["192.168.1.50", ""]})])
    assert svc.regler_dns(["192.168.1.50"])["dns"] == ["192.168.1.50"]
    assert len([a for a in f.appels if a[0] == "PUT"]) == 1 and journal[0]["action"] == "dns_dhcp"


def test_regler_dns_non_pris_en_compte_est_une_erreur(tmp_path):
    svc, _, _ = _pret(tmp_path, [ok({"dns": ["1.1.1.1"]}), ok({"dns": ["1.1.1.1"]}), ok({"dns": ["1.1.1.1"]})])
    with pytest.raises(C.ErreurFreebox):
        svc.regler_dns(["192.168.1.50"])


def test_regler_dns6_relit_les_deux_champs(tmp_path):
    avant = ok({"dns": [], "use_custom_dns": False})
    apres = ok({"dns": ["2001:db8::50"], "use_custom_dns": True})
    svc, _, _ = _pret(tmp_path, [avant, apres, apres])
    assert svc.regler_dns6(True, ["2001:db8::50"])["use_custom_dns"] is True


def test_poser_bail_vise_la_mac(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok({})])
    svc.poser_bail("AA:BB:CC:DD:EE:FF", "192.168.1.9")
    assert [a for a in f.appels if a[0] == "PUT"][0][1].endswith("dhcp/static_lease/AA:BB:CC:DD:EE:FF")

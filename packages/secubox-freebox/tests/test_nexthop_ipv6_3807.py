# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Next hop du préfixe IPv6 principal (#3807) : PUT du tableau delegations complet, relecture, audit."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

from api import client as c
from tests.test_pare_feu_ecriture import _pret, ok

LL = "fe80::250:43ff:fe84:252f"


def _cfg(nh0=""):
    return {"ipv6_enabled": True, "ipv6ll": "fe80::3a07:16ff:fe77:17d3",
            "delegations": [{"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": nh0},
                            {"prefix": "2a01:e0a:dec:c4e1::/64", "next_hop": ""}]}


def test_lire_rend_le_prefixe_principal(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(_cfg(LL))])
    assert svc.lire_nexthop() == {"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": LL}


def test_regler_envoie_tout_le_tableau_ne_change_que_le_premier(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(_cfg("")), ok(_cfg(LL)), ok(_cfg(LL))])
    r = svc.regler_nexthop(LL)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("connection/ipv6/config/")
    corps = json.loads(puts[0][3])
    assert list(corps) == ["delegations"]
    assert corps["delegations"] == [{"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": LL},
                                    {"prefix": "2a01:e0a:dec:c4e1::/64", "next_hop": ""}]
    assert r == {"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": LL, "change": True}
    assert journal[0]["action"] == "ipv6_next_hop" and journal[0]["avant"] == "" and journal[0]["apres"] == LL


def test_vide_rend_le_prefixe_a_la_freebox(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(_cfg(LL)), ok(_cfg("")), ok(_cfg(""))])
    assert svc.regler_nexthop("")["next_hop"] == ""
    corps = json.loads([a for a in f.appels if a[0] == "PUT"][0][3])
    assert corps["delegations"][0]["next_hop"] == ""


def test_deja_en_place_n_ecrit_rien(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok(_cfg(LL))])
    assert svc.regler_nexthop(LL)["change"] is False
    assert not [a for a in f.appels if a[0] == "PUT"]


def test_relecture_non_conforme_leve(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok(_cfg("")), ok(_cfg("")), ok(_cfg(""))])
    with pytest.raises(c.ErreurFreebox):
        svc.regler_nexthop(LL)
    assert journal and journal[0]["apres"] == ""


def test_sans_droit_settings_rien_n_est_ecrit(tmp_path):
    svc, f, _ = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.regler_nexthop(LL)
    assert not [a for a in f.appels if a[0] == "PUT"]


@pytest.mark.parametrize("mauvais", ["2a01:e0a:dec:c4e0::94", "192.168.1.1", "fe80::1%eth2", "fe80::1;reboot",
                                     "fe80::1 ", "vide", "zz::1", "::1"])
def test_adresse_non_lien_local_refusee_avant_tout_appel(tmp_path, mauvais):
    svc, f, _ = _pret(tmp_path, [])
    nb = len(f.appels)
    with pytest.raises(ValueError):
        svc.regler_nexthop(mauvais)
    assert len(f.appels) == nb


def _ctl():
    chemin = str(Path(__file__).resolve().parents[1] / "sbin" / "freeboxctl")
    spec = importlib.util.spec_from_loader("freeboxctl_3807", importlib.machinery.SourceFileLoader("freeboxctl_3807", chemin))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _Faux:
    def __init__(self):
        self.vu = []

    def lire_nexthop(self):
        return {"prefix": "2a01:e0a:dec:c4e0::/64", "next_hop": ""}

    def regler_nexthop(self, nh):
        self.vu.append(nh)
        if nh and not nh.startswith("fe80"):
            raise ValueError("next hop invalide")
        return {"prefix": "p", "next_hop": nh, "change": True}


def test_verbes_freeboxctl(monkeypatch, capsys):
    m = _ctl()
    faux = _Faux()
    monkeypatch.setattr(m, "_fabriquer", lambda: faux)
    assert m.main(["nexthop-lire"]) == 0
    assert json.loads(capsys.readouterr().out)["prefix"] == "2a01:e0a:dec:c4e0::/64"
    assert m.main(["nexthop-regler", "vide"]) == 0 and faux.vu[-1] == ""
    assert m.main(["nexthop-regler", LL]) == 0 and faux.vu[-1] == LL
    capsys.readouterr()
    assert m.main(["nexthop-regler", ""]) == 1        # chaîne vide littérale refusée : seul « vide » rend le préfixe
    assert m.main(["nexthop-regler", "2a01::1"]) == 1
    assert m.main(["nexthop-regler"]) == 2

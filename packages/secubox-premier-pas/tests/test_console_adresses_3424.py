# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3424 : la console dit où continuer dans un navigateur."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import adresses as A, console as C  # noqa: E402


def _itf(nom, *ips):
    return {"ifname": nom, "addr_info": [{"family": "inet", "local": i} for i in ips]}


JSON = json.dumps([_itf("lo", "127.0.0.1"), _itf("br-lxc", "10.0.3.1"), _itf("lxcbr0", "10.0.4.1"),
                   _itf("docker0", "172.17.0.1"), _itf("wg-mesh", "10.99.0.2"),
                   _itf("eth2", "203.0.113.7"), _itf("eth0", "192.168.1.20"), _itf("eth1", "169.254.3.3", "192.168.1.20")])


def test_filtrage_et_ordre_lan_puis_wan():
    assert A.ipv4_utiles(lambda: JSON) == ["192.168.1.20", "203.0.113.7"]


def test_sortie_invalide_ou_vide():
    assert A.ipv4_utiles(lambda: "pas du json") == []
    assert A.ipv4_utiles(lambda: "") == []


def test_rendu_nom_et_ip():
    assert A.lignes("gk6", ["192.168.1.20", "203.0.113.7"]) == [
        "Continuer dans un navigateur :", "https://gk6/premier-pas/",
        "ou https://192.168.1.20/premier-pas/", "ou https://203.0.113.7/premier-pas/"]


def test_rendu_surplus_et_sans_adresse():
    assert A.lignes("gk6", ["10.0.0.1", "10.0.0.2", "10.0.0.3"])[-1].endswith("(+1 autres)")
    assert "pas d'adresse" in A.lignes("", [])[-1]
    assert A.lignes("", ["10.0.0.1"])[1] == "https://10.0.0.1/premier-pas/"


class _C:
    def __init__(self, ips):
        self.adr, self.adr_t = ("gk6", ips), 0.0


def test_mise_a_jour_quand_une_ip_arrive_en_retard(monkeypatch):
    monkeypatch.setattr(A, "nom_hote", lambda *a: "gk6")
    c = _C([])
    f = C.Console.adresses_changees
    assert f(c, lambda: []) is False
    c.adr_t = 0.0
    assert f(c, lambda: ["192.168.1.9"]) is True and c.adr == ("gk6", ["192.168.1.9"])
    assert f(c, lambda: ["192.168.1.9"]) is False            # délai non écoulé : pas de relecture
    c.adr_t = 0.0
    assert f(c, lambda: ["192.168.1.9"]) is False            # inchangé : pas de redessin


def test_aucun_secret_dans_les_lignes():
    assert not any("jeton" in l.lower() or "mot" in l.lower() for l in A.lignes("gk6", ["10.0.0.1"]))

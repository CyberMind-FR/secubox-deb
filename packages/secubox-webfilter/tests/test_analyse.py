# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from webfilter import analyse, listes

L = "[1791090000] unbound[1234:0] reply: 192.168.1.95 evil.example.com. A IN NOERROR 0.000000 0 60"


def test_ligne_reply_valide():
    e = analyse.ligne(L)
    assert (e.ts, e.client, e.qname, e.qtype, e.rcode) == (1791090000, "192.168.1.95", "evil.example.com", "A", "NOERROR")


def test_types_ignores_et_lignes_etrangeres():
    assert analyse.ligne(L.replace(" A IN", " MX IN")) is None
    assert analyse.ligne(L.replace("reply:", "query:")) is None
    assert analyse.ligne("n'importe quoi") is None and analyse.ligne("") is None


def test_valeurs_hostiles_ignorees():
    assert analyse.ligne(L.replace("192.168.1.95", "pas-une-ip")) is None
    assert analyse.ligne(L.replace("evil.example.com.", "x" * 300 + ".com.")) is None
    assert analyse.ligne(L.replace("evil.example.com.", "bad name.com.")) is None
    assert analyse.ligne(L.replace("192.168.1.95", "fe80::1%eth0")) is None
    assert analyse.ligne(L.replace("evil.example.com.", "evil\x00.example.com.")) is None
    assert analyse.ligne("x" * 100000) is None


def test_ipv6_acceptee():
    assert analyse.ligne(L.replace("192.168.1.95", "2a01:e0a:dec:c4e0::200")).client == "2a01:e0a:dec:c4e0::200"


def test_prefixe_journalctl_accepte():
    assert analyse.ligne("oct. 04 08:00:00 gk2 unbound[1234]: " + L).qname == "evil.example.com"


def test_classer_premiere_categorie_en_ordre():
    idx = {"adulte": listes.Index.depuis(["example.com"]), "jeux": listes.Index.depuis(["example.com", "bet.example.org"])}
    assert analyse.classer("x.example.com", idx) == "adulte"
    assert analyse.classer("bet.example.org", idx) == "jeux"
    assert analyse.classer("sain.example.net", idx) is None

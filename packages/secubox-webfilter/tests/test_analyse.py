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


def test_classer_rend_la_categorie_et_l_entree_de_liste():
    idx = {"adulte": listes.Index.depuis(["example.com"]), "jeux": listes.Index.depuis(["example.com", "bet.example.org"])}
    assert analyse.classer("x.example.com", idx) == ("adulte", "example.com")
    assert analyse.classer("bet.example.org", idx) == ("jeux", "bet.example.org")
    assert analyse.classer("sain.example.net", idx) is None


def test_format_short_unix_de_journalctl():
    e = analyse.ligne("1791096961.220283 gk2 unbound[1222657]: [1222657:0] reply: 192.168.1.3 hall.gk3.secubox.in. AAAA IN NOERROR 0.026784 0 97")
    assert (e.ts, e.client, e.qname, e.qtype) == (1791096961, "192.168.1.3", "hall.gk3.secubox.in", "AAAA")


def test_format_cat_sans_horodatage_utilise_l_heure_fournie():
    e = analyse.ligne("[1222657:0] reply: 192.168.1.3 hall.gk3.secubox.in. A IN NOERROR 0.02 0 97", maintenant=lambda: 1791100000)
    assert e is not None and e.ts == 1791100000

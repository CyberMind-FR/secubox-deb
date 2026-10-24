# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Calcul des liens directs côté pair (#3133) : logique pure."""
import copy

from api import pairs_directs as pd

NOW = 1_000_000.0
MOI = "M" * 43 + "="
MAITRE = "A" * 43 + "="
K1 = "B" * 43 + "="
K2 = "C" * 43 + "="
K3 = "D" * 43 + "="


def cand(nom, cle, ip, ep=None):
    return {"name": nom, "public_key": cle, "mesh_ip": ip, "endpoint": ep or f"192.168.1.{ip.split('.')[-1]}:51820"}


def etat(*directs):
    return {
        "role": "peer", "public_key": MOI, "inconnu": {"x": 1},
        "peers": [{"public_key": MAITRE, "allowed_ips": "10.10.0.0/24", "mesh_ip": "10.10.0.1",
                   "name": "maitre", "endpoint": "192.168.1.1:51820", "extra": 7}, *directs],
    }


def direct(cle, ip, depuis=NOW - 10, nom="p"):
    return {"public_key": cle, "allowed_ips": ip + "/32", "mesh_ip": ip, "name": nom,
            "endpoint": "192.168.1.9:51820", "direct": True, "direct_depuis": depuis}


def calc(e, liste, poignees=None, refuses=None, now=NOW):
    return pd.calculer(e, liste, poignees or {}, now, refuses or {})


def test_rien_a_ajouter_pour_entrees_refusees():
    liste = [
        cand("maitre", MAITRE, "10.10.0.1"),            # le maître
        cand("moi", MOI, "10.10.0.7"),                   # soi-même
        cand("a\nb", K1, "10.10.0.8"),                   # nom hostile
        cand("ok", K1, "10.10.0.9", "1.2.3.4:51822"),    # endpoint public
        cand("ok", K1, "10.10.1.5"),                     # hors réseau
        "texte", None, 3, [],
    ]
    r = calc(etat(), liste)
    assert r["ajouts"] == [] and r["retraits"] == []


def test_cle_ou_ip_deja_non_directe():
    e = etat()
    e["peers"].append({"public_key": K1, "allowed_ips": "10.10.0.20/32", "mesh_ip": "10.10.0.20", "name": "x"})
    r = calc(e, [cand("n1", K1, "10.10.0.30"), cand("n2", K2, "10.10.0.20")])
    assert r["ajouts"] == []


def test_deux_ajouts():
    r = calc(etat(), [cand("a", K1, "10.10.0.2"), cand("b", K2, "10.10.0.3")])
    assert sorted(a["cle_publique"] for a in r["ajouts"]) == [K1, K2]


def test_doublons_dans_la_liste():
    r = calc(etat(), [cand("a", K1, "10.10.0.2"), cand("b", K1, "10.10.0.3"), cand("c", K2, "10.10.0.2")])
    assert len(r["ajouts"]) == 1


def test_direct_disparu_retire():
    r = calc(etat(direct(K1, "10.10.0.2")), [])
    assert r["retraits"] == [K1] and r["refuses"] == {}


def test_direct_sans_poignee_ancien_retire_et_refuse():
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 400))
    liste = [cand("a", K1, "10.10.0.2")]
    r = calc(e, liste)
    assert r["retraits"] == [K1] and r["refuses"] == {K1: NOW + 3600}
    e2 = pd.appliquer(e, r, NOW)
    r2 = calc(e2, liste, refuses=r["refuses"], now=NOW + 10)
    assert r2["ajouts"] == []
    r3 = calc(e2, liste, refuses=r["refuses"], now=NOW + 3601)
    assert [a["cle_publique"] for a in r3["ajouts"]] == [K1] and r3["refuses"] == {}


def test_direct_avec_poignee_recente_conserve():
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 400))
    r = calc(e, [cand("a", K1, "10.10.0.2")], {K1: NOW - 30})
    assert r["retraits"] == []


def test_direct_jeune_sans_poignee_conserve():
    r = calc(etat(direct(K1, "10.10.0.2", depuis=NOW - 60)), [cand("a", K1, "10.10.0.2")])
    assert r["retraits"] == [] and r["refuses"] == {}


def test_non_direct_jamais_retire():
    e = etat()
    e["peers"].append({"public_key": K1, "allowed_ips": "10.10.0.20/32", "mesh_ip": "10.10.0.20"})
    r = calc(e, [])
    assert r["retraits"] == []


def test_appliquer_preserve_et_ajoute():
    e = etat(direct(K3, "10.10.0.5"))
    avant = copy.deepcopy(e)
    r = calc(e, [cand("a", K1, "10.10.0.2"), cand("z", K3, "10.10.0.5")])
    n = pd.appliquer(e, r, NOW)
    assert e == avant                                   # entrée non modifiée
    assert n["inconnu"] == {"x": 1} and n["peers"][0] == avant["peers"][0]
    assert [p["public_key"] for p in n["peers"]] == [MAITRE, K3, K1]
    assert n["peers"][2] == {"public_key": K1, "allowed_ips": "10.10.0.2/32", "mesh_ip": "10.10.0.2", "name": "a",
                             "endpoint": "192.168.1.2:51820", "direct": True, "direct_depuis": int(NOW)}


def test_idempotence():
    e = etat()
    liste = [cand("a", K1, "10.10.0.2"), cand("b", K2, "10.10.0.3")]
    n = pd.appliquer(e, calc(e, liste), NOW)
    r = calc(n, liste, {K1: NOW, K2: NOW}, now=NOW + 5)
    assert r["ajouts"] == [] and r["retraits"] == []


def test_appliquer_ne_fait_pas_confiance_au_calcul():
    e = etat()
    mauvais = {"ajouts": [{"nom": "a\nb", "mesh_ip": "10.10.0.2", "cle_publique": K1, "endpoint": "192.168.1.2:1"}],
               "retraits": [MAITRE], "refuses": {}}
    n = pd.appliquer(e, mauvais, NOW)
    assert n["peers"] == e["peers"]                     # ni ajout hostile, ni retrait du maître


def test_entrees_hostiles_sans_exception():
    for bad in (None, 3, "x", {"peers": "x"}, {"peers": [1, None, "a"], "public_key": 5}):
        for liste in (None, "x", 5, [None, {"name": 1}]):
            r = pd.calculer(bad, liste, {K1: "abc", K2: float("nan")}, NOW, {K1: "x", 4: 5})
            assert r["ajouts"] == [] and r["retraits"] == []
    e = etat(direct(K1, "10.10.0.2", depuis="hier"))
    assert calc(e, [cand("a", K1, "10.10.0.2")], {K1: "x", K2: True})["retraits"] == []
    assert pd.appliquer(None, {}, NOW) == {}
    assert pd.appliquer({"peers": 3}, {"ajouts": 5}, NOW) == {"peers": 3}


def test_ip_locale_reservee():
    e = etat()
    e["address"] = "10.10.0.7/24"
    liste = [cand("a", K1, "10.10.0.7")]
    assert calc(e, liste)["ajouts"] == []
    forge = {"ajouts": [{"nom": "a", "mesh_ip": "10.10.0.7", "cle_publique": K1, "endpoint": "192.168.1.7:51820"}],
             "retraits": [], "refuses": {}}
    assert pd.appliquer(e, forge, NOW)["peers"] == e["peers"]


def test_ip_du_maitre_reservee_sans_mesh_ip():
    e = etat()
    del e["peers"][0]["mesh_ip"]
    assert calc(e, [cand("a", K1, "10.10.0.1")])["ajouts"] == []
    forge = {"ajouts": [{"nom": "a", "mesh_ip": "10.10.0.1", "cle_publique": K1, "endpoint": "192.168.1.7:51820"}],
             "retraits": [], "refuses": {}}
    assert pd.appliquer(e, forge, NOW)["peers"] == e["peers"]
    assert calc(e, [cand("a", K1, "10.10.0.255"), cand("b", K2, "10.10.0.0")])["ajouts"] == []

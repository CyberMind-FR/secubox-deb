# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Calcul des liens directs côté pair (#3133) : logique pure."""
import copy

from api import mesh
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


def direct(cle, ip, depuis=NOW - 10, nom="p", etat_d="actif"):
    e = {"public_key": cle, "mesh_ip": ip, "name": nom, "endpoint": "192.168.1.9:51820", "direct": True,
         "direct_etat": etat_d, "direct_depuis": depuis}
    if etat_d == "actif":
        e["allowed_ips"] = ip + "/32"
    return e


def calc(e, liste, poignees=None, now=NOW):
    return pd.calculer(e, liste, poignees or {}, now)


VIDE = {"ajouts": [], "promotions": [], "retrogradations": [], "retraits": []}


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
    for etat_d in ("actif", "sonde"):
        r = calc(etat(direct(K1, "10.10.0.2", etat_d=etat_d)), [])
        assert r == dict(VIDE, retraits=[K1])           # seul cas de suppression : le maître ne le liste plus


def test_actif_sans_poignee_ancien_retrograde_en_sonde_jamais_retire():
    # remplace l'ancien « retiré et refusé 1 h » : la sonde reste, le /32 disparaît, le trafic revient au maître
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 400))
    liste = [cand("a", K1, "10.10.0.2")]
    r = calc(e, liste)
    assert r == dict(VIDE, retrogradations=[K1])
    e2 = pd.appliquer(e, r, NOW)
    sonde = e2["peers"][1]
    assert sonde == {"public_key": K1, "mesh_ip": "10.10.0.2", "name": "p", "endpoint": "192.168.1.9:51820",
                     "direct": True, "direct_etat": "sonde", "direct_depuis": int(NOW)}
    assert calc(e2, liste, now=NOW + 10) == VIDE       # sans poignée : la sonde attend, rien d'autre
    r3 = calc(e2, liste, {K1: NOW + 20}, now=NOW + 30)  # la poignée revient : promotion immédiate
    assert r3 == dict(VIDE, promotions=[K1])
    e3 = pd.appliquer(e2, r3, NOW + 30)
    assert e3["peers"][1]["direct_etat"] == "actif" and e3["peers"][1]["allowed_ips"] == "10.10.0.2/32"
    assert e3["peers"][1]["direct_depuis"] == int(NOW + 30)


def test_sonde_promue_seulement_avec_poignee_recente():
    liste = [cand("a", K1, "10.10.0.2")]
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 4000, etat_d="sonde"))
    assert calc(e, liste) == VIDE                                   # jamais de poignée
    assert calc(e, liste, {K1: NOW - 181}) == VIDE                  # poignée trop ancienne
    assert calc(e, liste, {K1: NOW + 50}) == VIDE                   # poignée dans le futur : ignorée
    assert calc(e, liste, {K1: NOW - 179}) == dict(VIDE, promotions=[K1])


def test_actif_promu_recemment_garde_meme_sans_poignee():
    liste = [cand("a", K1, "10.10.0.2")]
    assert calc(etat(direct(K1, "10.10.0.2", depuis=NOW - 100)), liste) == VIDE
    for depuis in (None, "hier", NOW + 500, float("nan")):     # horodatage douteux : ne protège pas le /32
        assert calc(etat(direct(K1, "10.10.0.2", depuis=depuis)), liste) == dict(VIDE, retrogradations=[K1])


def test_entree_directe_sans_etat_est_une_sonde():
    e = etat(direct(K1, "10.10.0.2"))
    del e["peers"][1]["direct_etat"]                    # /32 présent mais état absent : traitée comme une sonde
    assert pd.etat_direct(e["peers"][1]) == "sonde"
    assert calc(e, [cand("a", K1, "10.10.0.2")], {K1: NOW - 5}) == dict(VIDE, promotions=[K1])


def test_promotion_revalide_l_ip():
    e = etat(direct(K1, "10.10.0.7", etat_d="sonde"))
    e["address"] = "10.10.0.7/24"                       # notre propre IP : jamais un /32 direct
    n = pd.appliquer(e, dict(VIDE, promotions=[K1]), NOW)
    assert n["peers"][1]["direct_etat"] == "sonde" and "allowed_ips" not in n["peers"][1]
    e = etat(direct(K1, "10.10.0.9", etat_d="sonde"), direct(K2, "10.10.0.9", etat_d="actif"))
    n = pd.appliquer(e, dict(VIDE, promotions=[K1]), NOW)
    assert n["peers"][1]["direct_etat"] == "sonde"       # IP déjà tenue par une autre entrée
    e = etat(direct(K1, "10.10.1.9", etat_d="sonde"))
    assert pd.appliquer(e, dict(VIDE, promotions=[K1]), NOW) == e      # hors réseau maillé


def test_appliquer_ne_touche_que_les_directs():
    e = etat()
    e["peers"].append({"public_key": K1, "allowed_ips": "10.10.0.20/32", "mesh_ip": "10.10.0.20"})
    calcul = {"ajouts": [], "promotions": [MAITRE, K1], "retrogradations": [MAITRE, K1], "retraits": [MAITRE, K1]}
    assert pd.appliquer(e, calcul, NOW) == e


def test_direct_avec_poignee_recente_conserve():
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 400))
    r = calc(e, [cand("a", K1, "10.10.0.2")], {K1: NOW - 30})
    assert r == VIDE


def test_direct_jeune_sans_poignee_conserve():
    r = calc(etat(direct(K1, "10.10.0.2", depuis=NOW - 60)), [cand("a", K1, "10.10.0.2")])
    assert r == VIDE


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
    assert n["peers"][2] == {"public_key": K1, "mesh_ip": "10.10.0.2", "name": "a",          # nouvelle = SONDE
                             "endpoint": "192.168.1.2:51820", "direct": True, "direct_etat": "sonde",
                             "direct_depuis": int(NOW)}


def test_idempotence():
    e = etat()
    liste = [cand("a", K1, "10.10.0.2"), cand("b", K2, "10.10.0.3")]
    n = pd.appliquer(e, calc(e, liste), NOW)
    assert calc(n, liste, now=NOW + 5) == VIDE                         # sondes sans poignée : rien
    p = pd.appliquer(n, calc(n, liste, {K1: NOW + 10, K2: NOW + 10}, now=NOW + 20), NOW + 20)
    assert [x.get("direct_etat") for x in p["peers"][1:]] == ["actif", "actif"]
    assert calc(p, liste, {K1: NOW + 10, K2: NOW + 10}, now=NOW + 25) == VIDE   # tant que les poignées tiennent


def test_appliquer_ne_fait_pas_confiance_au_calcul():
    e = etat()
    mauvais = {"ajouts": [{"nom": "a\nb", "mesh_ip": "10.10.0.2", "cle_publique": K1, "endpoint": "192.168.1.2:1"}],
               "retraits": [MAITRE]}
    n = pd.appliquer(e, mauvais, NOW)
    assert n["peers"] == e["peers"]                     # ni ajout hostile, ni retrait du maître


def test_entrees_hostiles_sans_exception():
    for bad in (None, 3, "x", {"peers": "x"}, {"peers": [1, None, "a"], "public_key": 5}):
        for liste in (None, "x", 5, [None, {"name": 1}]):
            assert pd.calculer(bad, liste, {K1: "abc", K2: float("nan")}, NOW) == VIDE
    e = etat(direct(K1, "10.10.0.2", depuis=NOW - 10))
    assert calc(e, [cand("a", K1, "10.10.0.2")], {K1: "x", K2: True})["retraits"] == []
    assert pd.calculer(etat(), [], {}, True) == VIDE and pd.calculer(etat(), [], {}, float("inf")) == VIDE
    assert pd.appliquer(etat(), {"promotions": "x", "retrogradations": 5, "retraits": None}, NOW) == etat()
    assert pd.appliquer(None, {}, NOW) == {}
    assert pd.appliquer({"peers": 3}, {"ajouts": 5}, NOW) == {"peers": 3}


def test_ip_locale_reservee():
    e = etat()
    e["address"] = "10.10.0.7/24"
    liste = [cand("a", K1, "10.10.0.7")]
    assert calc(e, liste)["ajouts"] == []
    forge = {"ajouts": [{"nom": "a", "mesh_ip": "10.10.0.7", "cle_publique": K1, "endpoint": "192.168.1.7:51820"}],
             "retraits": []}
    assert pd.appliquer(e, forge, NOW)["peers"] == e["peers"]


def test_ip_du_maitre_reservee_sans_mesh_ip():
    e = etat()
    del e["peers"][0]["mesh_ip"]
    assert calc(e, [cand("a", K1, "10.10.0.1")])["ajouts"] == []
    forge = {"ajouts": [{"nom": "a", "mesh_ip": "10.10.0.1", "cle_publique": K1, "endpoint": "192.168.1.7:51820"}],
             "retraits": []}
    assert pd.appliquer(e, forge, NOW)["peers"] == e["peers"]
    assert calc(e, [cand("a", K1, "10.10.0.255"), cand("b", K2, "10.10.0.0")])["ajouts"] == []


def _bloc(conf, cle):
    return next(b for b in conf.split("[Peer]")[1:] if f"PublicKey = {cle}\n" in b)


def test_rendu_sonde_sans_allowedips_et_jamais_le_reseau_entier():
    e = etat(direct(K1, "10.10.0.2", etat_d="sonde"), direct(K2, "10.10.0.3"))
    e.update(private_key="x", address="10.10.0.7/24")
    sans_ai = direct(K3, "10.10.0.4")
    del sans_ai["allowed_ips"]                          # « actif » mais sans allowed_ips : aucune ligne, pas le /24
    bizarre = direct(MOI[:-2] + "Q=", "10.10.0.5", etat_d="sonde")
    bizarre["allowed_ips"] = "10.10.0.5/32"            # sonde qui garderait un /32 : jamais rendu
    e["peers"] += [sans_ai, bizarre]
    conf = mesh.render_wg_conf(e)
    for cle in (K1, K3, bizarre["public_key"]):
        b = _bloc(conf, cle)
        assert "AllowedIPs" not in b and "Endpoint = 192.168.1.9:51820" in b and "PersistentKeepalive = 25" in b
    assert "AllowedIPs = 10.10.0.3/32" in _bloc(conf, K2)
    assert "AllowedIPs = 10.10.0.0/24" in _bloc(conf, MAITRE)
    assert conf.count("AllowedIPs = 10.10.0.0/24") == 1

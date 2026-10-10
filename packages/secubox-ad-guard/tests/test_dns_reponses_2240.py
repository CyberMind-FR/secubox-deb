# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2240 : détournement d'un domaine NORMAL, lu dans les RÉPONSES d'Unbound — il résout soudain vers une adresse ou un ASN inattendu."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.dnstv_reponses import accepter, analyser, ouvrir, parse_dump, reseau_de  # noqa: E402

JOUR = 86400
NOW = 1_800_000_000
ASN = {"93.184.216.34": 15133, "93.184.216.35": 15133, "151.101.1.1": 54113, "185.199.108.153": 54114, "104.16.0.1": 13335}
asn_de = lambda ip: ASN.get(ip)


def cx_vide():
    return ouvrir(":memory:")


def passe(cx, reponses, t, connus=("exemple.org",), clients=None):
    return analyser(cx, reponses, t, set(connus), asn_de, clients or {})


def test_parse_dump_ne_garde_que_les_adresses_a_et_aaaa_valides():
    texte = ("START_RRSET_CACHE\n;rrset 3595 1 0 8 0\nwww.exemple.org.\t3595\tIN\tA\t93.184.216.34\n"
             "www.exemple.org.\t3595\tIN\tCNAME\tcdn.exemple.org.\nv6.exemple.org.\t60\tIN\tAAAA\t2606:2800::1\n"
             "mauvais.\t1\tIN\tA\tpas-une-ip\nEND_RRSET_CACHE\n")
    assert sorted(parse_dump(texte)) == [("v6.exemple.org", "2606:2800::1"), ("www.exemple.org", "93.184.216.34")]


def test_reseau_prefere_l_asn_sinon_le_prefixe():
    assert reseau_de("93.184.216.34", asn_de) == "AS15133"
    assert reseau_de("45.77.3.4", asn_de) == "4:45.77"
    assert reseau_de("2001:db8:1234::1", asn_de) == "6:2001:db8"


def test_apprentissage_trois_jours_sans_alerte_puis_changement_de_reseau_signale():
    cx = cx_vide()
    for j in range(4):                                                   # 4 jours d'observation du même ASN
        assert passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR) == []
    f = passe(cx, [("www.exemple.org", "151.101.1.1")], NOW)           # soudain un autre ASN
    assert [(x["rule"], x["src_ip"]) for x in f] == [("dns.hijack.new_net", "151.101.1.1")] and f[0]["severity"] >= 60
    assert f[0]["domaine"] == "exemple.org" and "AS15133" in f[0]["detail"] and "AS54113" in f[0]["detail"]


def test_une_adresse_du_meme_asn_n_est_pas_un_detournement():
    cx = cx_vide()
    for j in range(4):
        passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR)
    assert passe(cx, [("www.exemple.org", "93.184.216.35")], NOW) == []


def test_pas_d_alerte_pendant_l_apprentissage():
    cx = cx_vide()
    passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - 3600)
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW) == []   # moins de 3 jours de référence


def test_un_domaine_a_rotation_de_reseaux_est_ecarte():
    cx = cx_vide()
    for j, ip in enumerate(["93.184.216.34", "151.101.1.1", "185.199.108.153", "104.16.0.1", "45.60.1.1", "52.1.1.1"]):
        passe(cx, [("www.exemple.org", ip)], NOW - 8 * JOUR + j * 3600)   # six réseaux dès le premier jour : CDN à rotation
    assert passe(cx, [("www.exemple.org", "45.33.1.1")], NOW) == []     # un réseau de plus : aucun signal, il est appris


def test_domaine_inconnu_de_l_historique_de_requetes_n_est_pas_juge():
    cx = cx_vide()
    for j in range(4):
        passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR, connus=())
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW, connus=()) == []


def test_un_nom_public_qui_resout_vers_une_adresse_privee_ou_nulle():
    cx = cx_vide()
    for j in range(4):
        passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR)
    f = passe(cx, [("www.exemple.org", "127.0.0.1")], NOW, clients={"exemple.org": "192.168.1.60"})
    assert [(x["rule"], x["src_ip"]) for x in f] == [("dns.hijack.special", "192.168.1.60")] and f[0]["severity"] >= 75


def test_un_nom_toujours_prive_n_est_pas_un_detournement():
    cx = cx_vide()
    for j in range(5):
        passe(cx, [("nas.exemple.org", "192.168.1.9")], NOW - (5 - j) * JOUR)   # jamais d'adresse publique : zone locale
    assert passe(cx, [("nas.exemple.org", "192.168.1.9")], NOW) == []


def test_une_adresse_suspecte_n_entre_pas_dans_la_reference():
    cx = cx_vide()
    for j in range(4):
        passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR)
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW)
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW + 3 * JOUR)   # toujours signalée trois jours plus tard : elle n'a pas été apprise


def test_accepter_un_domaine_apprend_son_nouveau_reseau():
    cx = cx_vide()
    for j in range(4):
        passe(cx, [("www.exemple.org", "93.184.216.34")], NOW - (4 - j) * JOUR)
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW)
    accepter(cx, "exemple.org", [("www.exemple.org", "151.101.1.1")], NOW, asn_de)
    assert passe(cx, [("www.exemple.org", "151.101.1.1")], NOW + 60) == []

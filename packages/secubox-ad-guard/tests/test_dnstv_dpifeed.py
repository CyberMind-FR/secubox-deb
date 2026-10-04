# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1960 : fichier d'échange d'ad-guard pour le DPI (agrégats par appareil du LAN : services, types, blocages — jamais les noms demandés)."""
import json
import os
import stat
import time

from api import dnstv, dnstv_dpifeed as F

T0 = 1_800_000_000
MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
SERVICES = dnstv.ClasseurServices([("ftven.fr", "France Télévisions", "contenu"), ("fwmrm.net", "FreeWheel", "publicite"),
                                   ("youboranqs01.com", "NPAW", "qualite_video")])
ETAT = {"actif": True, "clients": [{"ip": "192.168.1.128", "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto"},
                                   {"ip": V6, "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto"}]}
VOISINS = {"192.168.1.128": MAC, V6: MAC}


def build(compteurs, voisins=VOISINS, etat=ETAT, exclus=frozenset()):
    return F.construire(compteurs, voisins, etat, SERVICES, set(exclus), T0)


def par_nom(feed):
    return {a["nom"]: a for a in feed["appareils"]}


def test_deux_adresses_d_une_meme_mac_donnent_un_seul_appareil_avec_ses_totaux():
    f = build({"192.168.1.128": {"cloudreplay.ftven.fr": (30, 0), "7cd77.v.fwmrm.net": (6, 6)}, V6: {"k7.ftven.fr": (10, 0), "7cd77.v.fwmrm.net": (4, 4)}})
    assert len(f["appareils"]) == 1
    a = f["appareils"][0]
    assert a["nom"] == "TV fb5b" and a["mac"] == MAC and sorted(a["adresses"]) == sorted(["192.168.1.128", V6]) and a["mode"] == "auto" and a["origine"] == "auto"
    assert (a["requetes"], a["bloquees"], a["domaines"]) == (50, 10, 3)
    s = {x["organisation"]: x for x in a["services"]}
    assert (s["France Télévisions"]["requetes"], s["FreeWheel"]["requetes"], s["FreeWheel"]["bloquees"]) == (40, 10, 10) and s["FreeWheel"]["type"] == "publicite"
    assert a["types"] == {"contenu": 40, "publicite": 10}


def test_un_appareil_sans_mac_reste_separe_et_son_nom_vient_de_l_adresse_ou_de_la_mac():
    f = build({"192.168.1.77": {"x.example.org": (5, 0)}, "192.168.1.88": {"y.example.org": (3, 0)}}, voisins={"192.168.1.88": "aa:bb:cc:dd:ee:ff"}, etat={"actif": True, "clients": []})
    noms = {a["nom"] for a in f["appareils"]}
    assert noms == {"192.168.1.77", "appareil ee:ff"} and all(a["mode"] == "non déclaré" and a["origine"] == "" for a in f["appareils"])


def test_la_box_et_la_passerelle_sont_exclues():
    f = build({"192.168.1.200": {"a.example.org": (99, 0)}, "192.168.1.254": {"b.example.org": (9, 0)}, "192.168.1.128": {"k7.ftven.fr": (5, 0)}}, exclus={"192.168.1.200", "192.168.1.254"})
    assert [a["nom"] for a in f["appareils"]] == ["TV fb5b"]


def test_top_dix_services_trie_et_inconnus_regroupes():
    comp = {"192.168.1.128": {f"s{i}.example.org": (i + 1, 0) for i in range(30)}}
    comp["192.168.1.128"].update({"k7.ftven.fr": (500, 0)})
    a = build(comp)["appareils"][0]
    assert len(a["services"]) <= 10 and a["services"][0]["organisation"] == "France Télévisions"
    assert [x["requetes"] for x in a["services"]] == sorted((x["requetes"] for x in a["services"]), reverse=True)
    assert "(inconnu)" in {x["organisation"] for x in a["services"]} and a["domaines"] == 31


def test_bloquees_jamais_superieures_aux_requetes_et_appareils_tries():
    f = build({"192.168.1.128": {"a.ftven.fr": (10, 99)}, "192.168.1.5": {"b.example.org": (500, 0)}})
    assert all(a["bloquees"] <= a["requetes"] for a in f["appareils"]) and f["appareils"][0]["requetes"] >= f["appareils"][1]["requetes"]


def test_noms_hostiles_ni_comptes_ni_recopies_et_aucun_nom_de_domaine_dans_le_fichier():
    f = build({"192.168.1.128": {'x"; reboot.example.org': (99, 0), "AUTRE.Example.org": (99, 0), "cloudreplay.ftven.fr": (30, 0), "7cd77.v.fwmrm.net": (12, 12)}})
    brut = json.dumps(f, ensure_ascii=False)
    assert f["appareils"][0]["domaines"] == 2 and "reboot" not in brut
    for nom in ("cloudreplay", "fwmrm.net", "ftven.fr", "7cd77"):
        assert nom not in brut                                              # vie privée : jamais les noms demandés, seulement organisations et types
    assert "France Télévisions" in brut and "FreeWheel" in brut


def test_nom_d_appareil_hostile_dans_l_etat_est_borne():
    etat = {"actif": True, "clients": [{"ip": "192.168.1.128", "nom": "TV banc", "mode": "auto"}]}
    f = build({"192.168.1.128": {"a.ftven.fr": (1, 0)}}, voisins={}, etat=etat)
    assert f["appareils"][0]["nom"] == "TV banc"


def test_ecriture_atomique_permissions_et_relecture(tmp_path):
    f = build({"192.168.1.128": {"a.ftven.fr": (4, 1)}})
    F.ecrire_feed(f, tmp_path)
    p = tmp_path / "dpi-feed.json"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o640 and not list(tmp_path.glob(".dpifeed.*"))
    g = F.charger_feed(tmp_path)
    assert g["version"] == 1 and g["genere"] == T0 and g["appareils"][0]["requetes"] == 4


def test_lecture_refuse_lien_symbolique_fichier_corrompu_ou_inconnu(tmp_path):
    assert F.charger_feed(tmp_path / "absent") is None
    (tmp_path / "ailleurs.json").write_text(json.dumps({"version": 1, "genere": 1, "appareils": []}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "dpi-feed.json")
    assert F.charger_feed(tmp_path) is None
    (tmp_path / "dpi-feed.json").unlink()
    (tmp_path / "dpi-feed.json").write_text("{corrompu")
    assert F.charger_feed(tmp_path) is None
    (tmp_path / "dpi-feed.json").write_text(json.dumps({"version": 99, "genere": 1, "appareils": []}))
    assert F.charger_feed(tmp_path) is None


def test_compteurs_detail_requetes_et_bloquees(tmp_path):
    m = dnstv.Magasin(tmp_path / "m.db")
    t = int(time.time())
    m.ajouter([(dnstv.Evenement(t, "192.168.1.128", "k7.ftven.fr", "A", "NOERROR", "ALLOWED"), ""),
               (dnstv.Evenement(t, "192.168.1.128", "k7.ftven.fr", "A", "NXDOMAIN", "BLOCKED"), ""),
               (dnstv.Evenement(t - 5 * 86400, "192.168.1.128", "vieux.example.org", "A", "NOERROR", "ALLOWED"), "")])
    assert m.compteurs_detail(dnstv._jour(t - 86400)) == {"192.168.1.128": {"k7.ftven.fr": (2, 1)}}

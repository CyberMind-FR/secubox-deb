# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1959 : ajout automatique des appareils détectés, suivi de leurs adresses, plafonds et garde-fous."""
import copy
import json
import os

import pytest

from api import dnstv, dnstv_ajout as A, dnstv_auto as M, dnstv_detecteur as D, dnstv_regles as R

T0 = 1_800_000_000
MAC = "38:07:16:94:fb:5b"
V6 = "2a01:e0a:dec:c4e0:4951:bf00:df87:2c57"
VOISINS = {"192.168.1.128": MAC, V6: MAC}
REGLAGE = M.Reglage()
DET = [D.Detection(MAC, MAC, [V6, "192.168.1.128"], 80, "12 requêtes vers fwmrm.net ; services : France Télévisions, NPAW")]
PROFIL = [("videos-pub.ftv-publicite.fr", "profil de base"), ("c.2mdn.net", "profil de base")]


def monde(ajout_auto=True, clients=None, **kw):
    etat = dnstv.valider_etat({"actif": True, "ajout_auto": ajout_auto, "clients": clients or [], **kw})
    return etat, R.Regles(), {"ajouts": [], "dernier_changement": 0}


def lancer(etat, regles, suivi, det=DET, voisins=VOISINS, vues=None, maintenant=T0, reglage=REGLAGE):
    return A.appliquer(etat, regles, det, voisins, vues or {}, PROFIL, suivi, reglage, maintenant)


def test_ajout_complet_nom_mode_regles_confirmees_et_champs():
    etat, regles, suivi = monde()
    res = lancer(etat, regles, suivi)
    assert {c["nom"] for c in etat["clients"]} == {"TV fb5b"} and {c["ip"] for c in etat["clients"]} == {V6, "192.168.1.128"}
    assert all(c["mode"] == "auto" and c["origine"] == "auto" and c["mac"] == MAC and c["ajoute"] == T0 and "fwmrm.net" in c["preuve"] for c in etat["clients"])
    assert regles.actives("tv-fb5b") == ["c.2mdn.net", "videos-pub.ftv-publicite.fr"] and res["etat_modifie"] is True
    assert [c["type"] for c in res["changements"]] == ["ajout"] and suivi["ajouts"] == [T0] and suivi["dernier_changement"] == T0
    dnstv.valider_etat(etat)                                                  # l'état produit reste valide


def test_mode_par_defaut_respecte_et_regles_de_base_seulement_en_auto():
    etat, regles, suivi = monde(mode_defaut="observe")
    lancer(etat, regles, suivi)
    assert {c["mode"] for c in etat["clients"]} == {"observe"} and regles.liste() == []


def test_desactive_par_defaut_ne_change_rien():
    etat, regles, suivi = monde(ajout_auto=False)
    avant = copy.deepcopy(etat)
    assert lancer(etat, regles, suivi)["etat_modifie"] is False and etat == avant and regles.liste() == []


def test_mac_ignoree_ou_deja_connue_jamais_ajoutee():
    etat, regles, suivi = monde(ignores=[MAC])
    lancer(etat, regles, suivi)
    assert etat["clients"] == []
    etat, regles, suivi = monde(clients=[{"ip": "192.168.1.128", "nom": "TV salon", "mode": "auto", "mac": MAC}])
    lancer(etat, regles, suivi)
    assert [c["nom"] for c in etat["clients"] if c["ip"] == V6] == []         # l'appareil déclaré par l'administrateur n'est pas dupliqué


def test_plafond_quotidien_et_delai_entre_rechargements():
    etat, regles, suivi = monde()
    suivi["dernier_changement"] = T0 - 600                                   # moins d'une heure : différé, sans erreur
    assert lancer(etat, regles, suivi)["etat_modifie"] is False and etat["clients"] == []
    suivi = {"ajouts": [T0 - 3600 * i for i in (2, 3, 4)], "dernier_changement": T0 - 7200}     # déjà 3 ajouts sur 24 h
    assert lancer(etat, regles, suivi)["etat_modifie"] is False and etat["clients"] == []
    suivi = {"ajouts": [T0 - 3600 * i for i in (30, 40, 50)], "dernier_changement": T0 - 7200}   # ajouts de plus de 24 h : n'comptent plus
    assert lancer(etat, regles, suivi)["etat_modifie"] is True


def test_trente_deux_adresses_au_plus_sans_erreur_et_refus_visible():
    clients = [{"ip": f"192.168.1.{i}", "nom": f"Autre {i}", "mode": "observe"} for i in range(1, 32)]
    etat, regles, suivi = monde(clients=clients)
    res = lancer(etat, regles, suivi)                                        # 2 adresses n'entrent pas : 31 + 2 > 32
    assert len(etat["clients"]) == 31 and res["etat_modifie"] is False and [c["type"] for c in res["changements"]] == ["refus"]


def test_nouvelle_ipv6_rattachee_et_adresse_ancienne_retiree_mais_une_reste():
    etat, regles, suivi = monde()
    lancer(etat, regles, suivi)
    neuve = "2a01:e0a:dec:c4e0:9999:1:2:3"
    plus_tard = T0 + 8 * 86400
    res = lancer(etat, regles, suivi, det=[], voisins={"192.168.1.128": MAC, neuve: MAC}, vues={"192.168.1.128": plus_tard, neuve: plus_tard, V6: T0}, maintenant=plus_tard)
    assert {c["ip"] for c in etat["clients"]} == {"192.168.1.128", neuve} and res["etat_modifie"] is True
    assert {c["type"] for c in res["changements"]} == {"adresse+", "adresse-"}
    assert {c["nom"] for c in etat["clients"]} == {"TV fb5b"} and all(c["mac"] == MAC and c["origine"] == "auto" for c in etat["clients"])
    lancer(etat, regles, suivi, det=[], voisins={}, vues={}, maintenant=T0 + 30 * 86400)
    assert len(etat["clients"]) >= 1                                          # une adresse au moins reste toujours


def test_adresses_locales_de_lien_et_adresses_invalides_ignorees():
    etat, regles, suivi = monde()
    lancer(etat, regles, suivi)
    voisins = {"192.168.1.128": MAC, "fe80::771c:5e8e:925b:400": MAC, "ff02::1": MAC, "pas-une-ip": MAC}
    lancer(etat, regles, suivi, det=[], voisins=voisins, maintenant=T0 + 7200)
    assert {c["ip"] for c in etat["clients"]} == {V6, "192.168.1.128"}        # ni lien-local, ni multicast, ni texte


def test_les_appareils_declares_par_l_administrateur_ne_sont_pas_suivis():
    etat, regles, suivi = monde(clients=[{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}])
    lancer(etat, regles, suivi, det=[], voisins={"192.168.1.95": "38:07:16:93:4e:95", "2a01::95": "38:07:16:93:4e:95"})
    assert [c["ip"] for c in etat["clients"]] == ["192.168.1.95"]


def test_nom_unique_et_conforme():
    assert A.nom_appareil(MAC, set()) == "TV fb5b" and A.nom_appareil(MAC, {"tv-fb5b"}) == "TV fb5b-2" and A.nom_appareil(MAC, {"tv-fb5b", "tv-fb5b-2"}) == "TV fb5b-3"
    assert dnstv.NOM_RE.match(A.nom_appareil(MAC, set()))


def test_deux_appareils_dont_les_mac_finissent_pareil_ont_des_noms_distincts():
    mac2 = "aa:bb:cc:dd:fb:5b"
    det = [D.Detection(MAC, MAC, ["192.168.1.128"], 80, "p"), D.Detection(mac2, mac2, ["192.168.1.129"], 70, "p")]
    etat, regles, suivi = monde()
    lancer(etat, regles, suivi, det=det, voisins={"192.168.1.128": MAC, "192.168.1.129": mac2}, reglage=M.Reglage(max_par_jour=5))
    assert len({c["nom"] for c in etat["clients"]}) == 2
    dnstv.valider_etat(etat)


def test_detection_hostile_jamais_ecrite():
    for det in ([D.Detection("38:07:16:94:FB:5B", "x", ["192.168.1.128"], 90, "p")],
                [D.Detection("00:00:00:00:00:00", "x", ["192.168.1.128"], 90, "p")],
                [D.Detection(MAC, MAC, ['1.2.3.4"; reboot', "pas-une-ip"], 90, "<img>")]):
        etat, regles, suivi = monde()
        lancer(etat, regles, suivi, det=det)
        assert etat["clients"] == [] and regles.liste() == []


def test_suivi_stockage_atomique_et_validation(tmp_path):
    A.ecrire_suivi({"ajouts": [T0], "dernier_changement": T0}, tmp_path)
    assert A.charger_suivi(tmp_path) == {"ajouts": [T0], "dernier_changement": T0}
    (tmp_path / "suivi-ajout.json").unlink()
    (tmp_path / "ailleurs.json").write_text(json.dumps({"ajouts": [1], "dernier_changement": 1}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "suivi-ajout.json")
    assert A.charger_suivi(tmp_path) == {"ajouts": [], "dernier_changement": 0}      # lien refusé : suivi vierge
    (tmp_path / "suivi-ajout.json").unlink()
    (tmp_path / "suivi-ajout.json").write_text('{"ajouts": ["x"], "dernier_changement": "y"}')
    assert A.charger_suivi(tmp_path) == {"ajouts": [], "dernier_changement": 0}
    assert A.charger_suivi(tmp_path / "absent") == {"ajouts": [], "dernier_changement": 0}


def test_reglage_a_les_seuils_de_depart():
    r = M.Reglage()
    assert (r.max_par_jour, r.delai_s, r.retrait_jours, r.min_declencheurs, r.min_services, r.min_appareils_agreg) == (3, 3600, 7, 5, 2, 2)
    with pytest.raises(TypeError):
        M.Reglage(inconnu=1)

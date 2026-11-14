# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Règles fermées des macros (#3702, tâche 2) : aucune étape hors liste, bornes, comparaisons."""
import pytest

from pilotage.macros import (LIVREES, MacroInvalide, comparer, contient_forte, estimer_s, coupure, evaluer_condition, instantane,
                             services_en_echec, valider_etapes, valider_nom, valider_programmation)

REBOOT = {"type": "action", "action": "reboot"}
RELEVE = {"type": "releve", "duree_s": 60, "nom": "avant"}
COND = {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "arreter"}
CMP = {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "nouveau_service_en_echec", "seuil": 0}
CMP_MEM = {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "memoire_dispo_baisse_mo", "seuil": 150}


def inst(services=None, n=None, mem=None):
    return {"memoire_dispo_mo": mem, "cpu_pct": None, "swap_utilise_pct": None, "services_en_echec": n, "services": services,
            "inventaire_le": 1}


@pytest.mark.parametrize("etapes", [
    [{"type": "shell"}], [{"type": "action", "action": "rm"}], [{"type": "action", "action": "reboot", "cmd": "x"}],
    [REBOOT] * 21, [], "x", [42], [{"type": "action"}], [{"type": "action", "action": ["reboot"]}],
])
def test_etapes_hors_liste_refusees(etapes):
    with pytest.raises(MacroInvalide):
        valider_etapes(etapes)


@pytest.mark.parametrize("etape", [
    {"type": "action", "action": "reboot", "delai_s": 59}, {"type": "action", "action": "reboot", "delai_s": 3601},
    {"type": "action", "action": "reboot", "delai_s": True},
    {"type": "releve", "duree_s": 9, "nom": "a"}, {"type": "releve", "duree_s": 301, "nom": "a"},
    {"type": "releve", "duree_s": True, "nom": "a"}, {"type": "releve", "duree_s": 60, "nom": "A"},
    {"type": "releve", "duree_s": 60, "nom": "x" * 21},
    {"type": "attendre", "delai_s": 29}, {"type": "attendre", "delai_s": 901},
])
def test_bornes_des_etapes(etape):
    with pytest.raises(MacroInvalide):
        valider_etapes([etape])


@pytest.mark.parametrize("seuil", [True, "3", float("nan"), float("inf"), 1e6 + 1, None, 10**400, -10**400])
def test_seuil_refuse(seuil):
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, {**COND, "seuil": seuil}])


def test_seuil_aux_limites_et_valeurs_fermees():
    assert valider_etapes([RELEVE, {**COND, "seuil": -1e6}])[1]["seuil"] == -1e6
    for k, v in (("mesure", "disque"), ("op", "=="), ("alors", "rm"), ("releve", "x y")):
        with pytest.raises(MacroInvalide):
            valider_etapes([RELEVE, {**COND, k: v}])


def test_defauts_poses():
    (e,) = valider_etapes([{"type": "action", "action": "maj-paquets"}])
    assert e["delai_s"] == 900 and e["args"] == {}
    assert valider_etapes([{"type": "attendre"}])[0]["delai_s"] == 300
    assert valider_etapes([RELEVE, {"type": "releve", "duree_s": 60, "nom": "apres"},
                           {k: v for k, v in CMP.items() if k != "seuil"}])[2]["seuil"] == 0


def test_comparer_deux_relevés_identiques_refuse():
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, {**CMP, "apres": "avant"}])


def test_condition_sans_seuil_refusee():
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, {k: v for k, v in COND.items() if k != "seuil"}])


def test_message_borne_sur_cles_utilisateur():
    with pytest.raises(MacroInvalide) as e:
        valider_etapes([{"type": "attendre", **{"k" * 500 + str(i): 1 for i in range(50)}}])
    assert len(str(e.value)) < 400


@pytest.mark.parametrize("etape", [
    {"type": "action", "action": "service-redemarrer"},
    {"type": "action", "action": "service-redemarrer", "args": {"unite": "ssh.service"}},
    {"type": "action", "action": "service-redemarrer", "args": {"unite": "secubox-a.service", "x": "y"}},
    {"type": "action", "action": "reboot", "args": {"x": "y"}},
])
def test_args_valides_par_arguments(etape):
    with pytest.raises(MacroInvalide):
        valider_etapes([etape])


def test_args_valides_acceptes():
    (e,) = valider_etapes([{"type": "action", "action": "service-redemarrer", "args": {"unite": "secubox-a.service"}}])
    assert e["args"] == {"unite": "secubox-a.service"}


def test_releve_reference_doit_preceder():
    with pytest.raises(MacroInvalide):
        valider_etapes([COND, RELEVE])
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, RELEVE])
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, CMP])
    with pytest.raises(MacroInvalide):
        valider_etapes([RELEVE, {"type": "releve", "duree_s": 60, "nom": "apres"}, {**CMP, "avant": "zzz"}])
    assert len(valider_etapes([RELEVE, {"type": "releve", "duree_s": 60, "nom": "apres"}, CMP])) == 3


def test_nom_de_macro():
    assert valider_nom("Mise à jour sûre") == "Mise à jour sûre"
    for mauvais in ("a(b)", "", "x" * 61, "x\n", None, 5):
        with pytest.raises(MacroInvalide):
            valider_nom(mauvais)


def test_programmation_refusee_si_forte_ou_cliente():
    with pytest.raises(MacroInvalide):
        valider_programmation({"quotidien": "03:00"}, [REBOOT], cibles_clientes=False)
    with pytest.raises(MacroInvalide):
        valider_programmation({"quotidien": "03:00"}, [RELEVE], cibles_clientes=True)
    assert valider_programmation({"quotidien": "03:00"}, [RELEVE], False) == {"quotidien": "03:00"}
    assert valider_programmation(None, [RELEVE], False) is None
    for mauvaise in ({"quotidien": "24:00"}, {"quotidien": "3:00"}, {"quotidien": "03:00\n"}, {"hebdo": "03:00"},
                     {"quotidien": "03:00", "x": 1}, "03:00", {"quotidien": 300}):
        with pytest.raises(MacroInvalide):
            valider_programmation(mauvaise, [RELEVE], False)


def test_livrees_valides_et_retour_en_local_forte():
    assert len(LIVREES) == 4
    for m in LIVREES:
        assert valider_etapes(m["etapes"])
        valider_nom(m["nom"])
    assert {m["id"] for m in LIVREES if contient_forte(valider_etapes(m["etapes"]))} == {"livree:retour-en-local"}


def test_services_en_echec_depuis_l_inventaire():
    v = {"Device.X_SECUBOX_Services.1.Name": "secubox-a.service", "Device.X_SECUBOX_Services.1.ActiveState": "failed",
         "Device.X_SECUBOX_Services.2.Name": "nginx.service", "Device.X_SECUBOX_Services.2.ActiveState": "active",
         "Device.X_SECUBOX_Services.4.Name": "zz.service", "Device.X_SECUBOX_Services.4.ActiveState": "failed"}
    assert services_en_echec(v) == ["secubox-a.service"]   # arrêt au premier Name absent (3)
    assert services_en_echec({}) == []


def test_instantane():
    r = {"memoire_dispo_mo": 900, "cpu_pct": 1.5, "swap_utilise_pct": 3, "services_en_echec": 1, "inventaire_le": 7}
    v = {"Device.X_SECUBOX_Services.1.Name": "a", "Device.X_SECUBOX_Services.1.ActiveState": "failed"}
    assert instantane(r, v) == {**r, "services": ["a"]}
    assert instantane({}, {})["services"] is None and instantane({}, {})["memoire_dispo_mo"] is None


def test_condition_mesure_absente_fausse():
    c = {**COND}
    assert evaluer_condition(c, {"avant": {"services_en_echec": None}}) == {"vrai": False, "mesure_absente": True, "valeur": None}
    assert evaluer_condition(c, {})["mesure_absente"] is True
    assert evaluer_condition(c, {"avant": {"services_en_echec": 2}}) == {"vrai": True, "mesure_absente": False, "valeur": 2}
    assert evaluer_condition({**c, "op": "<"}, {"avant": {"services_en_echec": 2}})["vrai"] is False
    assert evaluer_condition(c, {"avant": {"services_en_echec": 0}})["vrai"] is False


def test_comparer_nouveau_service_et_compteur_sans_nom():
    r = comparer(CMP, {"avant": inst(services=[], n=0), "apres": inst(services=["secubox-portal.service"], n=1)})
    assert r["ecart"] and r["nouveaux"] == ["secubox-portal.service"]
    assert r["propositions"][0] == {"action": "service-redemarrer", "args": {"unite": "secubox-portal.service"}}
    assert comparer(CMP, {"avant": inst(services=["a"], n=1), "apres": inst(services=["a"], n=2)})["ecart"]   # hausse sans nom
    r = comparer(CMP, {"avant": inst(services=["a"], n=1), "apres": inst(services=["a"], n=1)})
    assert not r["ecart"] and not r["mesure_absente"] and r["propositions"] == []
    r = comparer(CMP, {"avant": inst(), "apres": inst()})
    assert not r["ecart"] and r["mesure_absente"]
    assert comparer(CMP, {})["mesure_absente"]


def test_comparer_baisse_memoire():
    pair = {"avant": inst(mem=900), "apres": inst(mem=700)}
    r = comparer(CMP_MEM, pair)
    assert r["ecart"] and r["baisse_mo"] == 200
    assert not comparer({**CMP_MEM, "seuil": 250}, pair)["ecart"]
    r = comparer(CMP_MEM, {"avant": inst(mem=None), "apres": inst(mem=700)})
    assert not r["ecart"] and r["mesure_absente"]


def test_estimation_et_coupure():
    (reb,) = valider_etapes([REBOOT])
    assert estimer_s(reb) == 120 and coupure(reb) == "redémarrage"
    assert estimer_s(valider_etapes([RELEVE])[0]) == 70
    assert estimer_s({"type": "action", "action": "reboot", "delai_s": 60}) == 60
    assert estimer_s(valider_etapes([{"type": "attendre", "delai_s": 40}])[0]) == 40
    assert estimer_s(valider_etapes([RELEVE, COND])[1]) == 0
    assert coupure({"type": "action", "action": "interface-locale"}) == "bascule d'interface"
    assert coupure({"type": "action", "action": "renommer"}) == "changement de nom"
    assert coupure({"type": "action", "action": "maj-paquets"}) is None and coupure(RELEVE) is None


def test_renommer_refuse_dans_une_macro():
    """Le renommage change la clé de la box en cours de macro : refusé à l'enregistrement comme au lancement (action seule)."""
    with pytest.raises(MacroInvalide, match="renommer"):
        valider_etapes([{"type": "action", "action": "renommer", "args": {"nom": "gk9"}}])
    assert all(e.get("action") != "renommer" for m in LIVREES for e in m["etapes"])

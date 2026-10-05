# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les appareils DÉCLARÉS À LA MAIN qui portent une MAC suivent leurs adresses IPv6 temporaires.

Une TV change d'IPv6 « de confidentialité » régulièrement. Tant que seules les adresses des appareils
ajoutés automatiquement étaient suivies, une TV déclarée par l'administrateur sortait de sa vue Unbound
au premier changement d'adresse : ses exceptions (imasdk.googleapis.com…) ne s'appliquaient plus et le
replay restait sur sa roue.
"""
from api import dnstv, dnstv_ajout as A, dnstv_auto as M, dnstv_regles as R

T0 = 1_800_000_000
MAC = "38:07:16:93:4e:95"
V4 = "192.168.1.95"
V6_ANCIEN = "2a01:e0a:dec:c4e0:c147:c3cf:6dd7:3429"
V6_NEUF = "2a01:e0a:dec:c4e0:8564:1c:9725:d96"
REGLAGE = M.Reglage()
DECLARES = [{"ip": V4, "nom": "TV banc", "mode": "auto", "mac": MAC},
            {"ip": V6_ANCIEN, "nom": "TV banc", "mode": "auto", "mac": MAC}]


def monde(clients):
    etat = dnstv.valider_etat({"actif": True, "ajout_auto": True, "clients": clients})
    return etat, R.Regles(), {"ajouts": [], "dernier_changement": 0}


def passe(etat, regles, suivi, voisins, vues, maintenant=T0):
    return A.appliquer(etat, regles, [], voisins, vues, [], suivi, REGLAGE, maintenant)


def test_une_nouvelle_ipv6_d_un_appareil_declare_est_rattachee():
    etat, regles, suivi = monde(DECLARES)
    res = passe(etat, regles, suivi, {V4: MAC, V6_NEUF: MAC}, {V4: T0, V6_NEUF: T0})
    assert V6_NEUF in {c["ip"] for c in etat["clients"]} and res["etat_modifie"] is True
    ajoute = next(c for c in etat["clients"] if c["ip"] == V6_NEUF)
    assert ajoute["nom"] == "TV banc" and ajoute["mac"] == MAC and ajoute["mode"] == "auto"


def test_l_adresse_ajoutee_est_marquee_suivi_et_survit_a_la_validation():
    etat, regles, suivi = monde(DECLARES)
    passe(etat, regles, suivi, {V4: MAC, V6_NEUF: MAC}, {V4: T0, V6_NEUF: T0})
    relu = dnstv.valider_etat(etat)
    ajoute = next(c for c in relu["clients"] if c["ip"] == V6_NEUF)
    assert ajoute.get("origine") == "suivi"


def test_les_adresses_declarees_ne_sont_jamais_retirees():
    etat, regles, suivi = monde(DECLARES)
    passe(etat, regles, suivi, {}, {}, maintenant=T0 + 90 * 86400)
    assert {c["ip"] for c in etat["clients"]} == {V4, V6_ANCIEN}


def test_une_adresse_suivie_perimee_est_retiree_mais_pas_les_declarees():
    etat, regles, suivi = monde(DECLARES)
    passe(etat, regles, suivi, {V4: MAC, V6_NEUF: MAC}, {V4: T0, V6_NEUF: T0})
    passe(etat, regles, suivi, {V4: MAC}, {V4: T0}, maintenant=T0 + 90 * 86400)
    assert {c["ip"] for c in etat["clients"]} == {V4, V6_ANCIEN}


def test_un_appareil_sans_mac_n_est_pas_suivi():
    etat, regles, suivi = monde([{"ip": V4, "nom": "TV banc", "mode": "auto"}])
    passe(etat, regles, suivi, {V4: MAC, V6_NEUF: MAC}, {V4: T0, V6_NEUF: T0})
    assert {c["ip"] for c in etat["clients"]} == {V4}


def test_le_plafond_d_adresses_par_appareil_tient():
    etat, regles, suivi = monde(DECLARES)
    voisins = {V4: MAC}
    for i in range(1, 8):
        voisins[f"2a01:e0a:dec:c4e0:{i:x}:1:2:3"] = MAC
    passe(etat, regles, suivi, voisins, {a: T0 for a in voisins})
    assert len([c for c in etat["clients"] if c.get("mac") == MAC]) <= A.ADRESSES_MAX_PAR_APPAREIL

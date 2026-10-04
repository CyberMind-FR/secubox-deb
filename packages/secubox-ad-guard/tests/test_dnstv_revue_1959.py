# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Passe de correction après la relecture de sécurité de l'ajout automatique (#1959) : un test par constat Critique/Important."""
import inspect
import threading
import time

import pytest

from api import dnstv, dnstv_ajout as A, dnstv_auto as M, dnstv_detecteur as D, dnstv_regles as R
from test_dnstv_ajout import DET, MAC, PROFIL, REGLAGE, T0, V6, VOISINS, lancer, monde
from test_dnstv_ajout_moteur import charger_script, donnees_tv, lancer as lancer_script
from test_dnstv_auto_rendu import charger_ctl, faux


# ── C1 : un identifiant de portée IPv6 ne s'écrit jamais dans la configuration d'Unbound ─────────────────────────────────────
HOSTILES = ["fe80::1%eth2", "fe80::1%eth2 sbx-tv-observe\n    local-data: \"banque.example. A 203.0.113.9\"\n    #",
            "192.168.1.1#x", "::1%lo\nserver:", "2a01::1%", "192.168.1.1 \nlocal-zone: x", "1.2.3.4;reboot"]    # un blanc ou saut de ligne en bout est retiré, jamais au milieu


def test_c1_ip_refuse_toute_portee_et_tout_caractere_inattendu():
    for h in HOSTILES:
        with pytest.raises(dnstv.ErreurTV):
            dnstv._ip(h)
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [{"ip": h, "nom": "TV", "mode": "observe"}]})
    assert dnstv._ip("2a01:E0A::0001") == "2a01:e0a::1" and dnstv._ip(" 192.168.1.9 ") == "192.168.1.9"


def test_c1_le_rendu_refuse_une_adresse_non_conforme_meme_si_la_validation_est_contournee(monkeypatch):
    etat = {"actif": True, "clients": [{"ip": "192.168.1.9", "nom": "TV", "mode": "observe"}], "auto_essai": False, "mode_defaut": "auto", "ajout_auto": False, "ignores": []}
    monkeypatch.setattr(dnstv, "valider_etat", lambda e: dict(e, clients=[{"ip": "fe80::1%eth2\nlocal-data: x", "nom": "TV", "mode": "observe"}]))
    with pytest.raises(dnstv.ErreurTV):
        dnstv.rendre_unbound(etat, {})


# ── I1 : l'état est lu SOUS le verrou, une action de l'administrateur n'est pas écrasée ───────────────────────────────────────
def test_i1_le_moteur_relit_l_etat_apres_avoir_pris_le_verrou(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    pris, fini = threading.Event(), threading.Event()

    def administrateur():
        with R.verrou(tmp_path):
            pris.set()
            time.sleep(0.4)
            dnstv.ecrire_etat({"actif": True, "ajout_auto": False, "clients": []}, tmp_path)         # l'administrateur désactive pendant que le moteur attend
        fini.set()
    th = threading.Thread(target=administrateur)
    th.start()
    pris.wait(2)
    appels = []
    from test_dnstv_auto_moteur import Rep
    assert lancer_script(mod, lambda: appels.append(1) or Rep(), t) == 0
    th.join()
    etat, _ = dnstv.lire_etat(tmp_path)
    assert etat["ajout_auto"] is False and etat["clients"] == [] and appels == []                  # la désactivation de l'administrateur est respectée


def test_i1_routes_qui_ecrivent_l_etat_sont_synchrones_et_verrouillees():
    from api import dnstv_routes as r
    src = inspect.getsource(r)
    for nom in ("activer", "declarer_client", "retirer_client", "changer_mode"):
        f = getattr(r, nom)
        assert not inspect.iscoroutinefunction(f), nom
        assert "_verrou()" in inspect.getsource(f), nom


# ── I2 : mode par défaut sûr, voisins du LAN seulement ────────────────────────────────────────────────────────────────────────
def test_i2_mode_defaut_limite_a_auto_ou_off():
    for ok in ("auto", "off"):
        assert dnstv.valider_etat({"actif": True, "clients": [], "mode_defaut": ok})["mode_defaut"] == ok
    for mauvais in ("observe", "block", "inconnu"):
        with pytest.raises(dnstv.ErreurTV):
            dnstv.valider_etat({"actif": True, "clients": [], "mode_defaut": mauvais})


def test_i2_voisins_filtres_par_interface_et_interface_du_lan():
    class R:
        stdout = ('[{"dst":"192.168.1.128","lladdr":"38:07:16:94:FB:5B","dev":"eth2"},{"dst":"10.100.0.20","lladdr":"aa:bb:cc:dd:ee:ff","dev":"br-lxc"},'
                  '{"dst":"10.99.1.2","lladdr":"11:22:33:44:55:66","dev":"wg-toolbox"}]')
    v = dnstv.lire_voisins(executer=lambda *a, **k: R(), interface="eth2")
    assert v == {"192.168.1.128": "38:07:16:94:fb:5b"}
    assert len(dnstv.lire_voisins(executer=lambda *a, **k: R())) == 3                               # sans filtre : comportement historique

    class Rr:
        stdout = '[{"dst":"default","gateway":"192.168.1.254","dev":"eth2"}]'
    assert dnstv.interface_lan(executer=lambda *a, **k: Rr()) == "eth2"
    assert dnstv.interface_lan(executer=lambda *a, **k: (_ for _ in ()).throw(OSError())) is None


def test_i2_le_script_n_ajoute_rien_si_l_interface_du_lan_est_inconnue(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": []})
    donnees_tv(tmp_path, t)
    monkeypatch.setattr(dnstv, "interface_lan", lambda executer=None: None)
    vus = {}
    monkeypatch.setattr(dnstv, "lire_voisins", lambda executer=None, interface=None: vus.setdefault("appel", interface) or {"192.168.1.128": MAC})
    from test_dnstv_auto_moteur import Rep
    assert mod.main(sudo=lambda: Rep(), maintenant=t, locales=lambda: set(), passerelles=lambda: set()) == 0
    assert dnstv.lire_etat(tmp_path)[0]["clients"] == []


# ── I3 : suivi des adresses borné, actif, sans passerelle ──────────────────────────────────────────────────────────────────────
def amorce():
    etat, regles, suivi = monde()
    lancer(etat, regles, suivi, vues={"192.168.1.128": T0, V6: T0})
    return etat, regles, suivi


def test_i3_une_adresse_sans_activite_dns_n_est_pas_rattachee():
    etat, regles, suivi = amorce()
    morte = "2a01:e0a:dec:c4e0:dead:beef:0:1"
    lancer(etat, regles, suivi, det=[], voisins={**VOISINS, morte: MAC}, vues={"192.168.1.128": T0 + 7300}, maintenant=T0 + 7300)
    assert morte not in {c["ip"] for c in etat["clients"]}                                           # jamais vue en DNS : entrée STALE du noyau, ignorée
    lancer(etat, regles, suivi, det=[], voisins={**VOISINS, morte: MAC}, vues={morte: T0 + 7400}, maintenant=T0 + 14600)
    assert morte in {c["ip"] for c in etat["clients"]}                                               # vue en DNS depuis : rattachée


def test_i3_adresses_au_plus_quatre_par_appareil():
    etat, regles, suivi = amorce()
    voisins = dict(VOISINS)
    vues = {}
    for i in range(10):
        a = f"2a01:e0a:dec:c4e0::{i + 10:x}"
        voisins[a] = MAC
        vues[a] = T0 + 9000
    lancer(etat, regles, suivi, det=[], voisins=voisins, vues=vues, maintenant=T0 + 9000)
    assert len([c for c in etat["clients"] if c["mac"] == MAC]) <= A.ADRESSES_MAX_PAR_APPAREIL == 4


def test_i3_les_exclus_ne_sont_jamais_rattaches_meme_via_une_mac_connue():
    etat, regles, suivi = amorce()
    passerelle = "2a01:e0a:dec:c4e0::1"
    A.appliquer(etat, regles, [], {**VOISINS, passerelle: MAC}, {passerelle: T0 + 8000}, PROFIL, suivi, REGLAGE, T0 + 8000, exclus={passerelle})
    assert passerelle not in {c["ip"] for c in etat["clients"]}


def test_i3_une_adresse_retiree_pour_inactivite_n_est_pas_rajoutee_en_boucle():
    etat, regles, suivi = amorce()
    morte = "2a01:e0a:dec:c4e0:dead:beef:0:2"
    voisins = {**VOISINS, morte: MAC}
    lancer(etat, regles, suivi, det=[], voisins=voisins, vues={morte: T0 + 3900}, maintenant=T0 + 4000)           # vue en DNS : rattachée (délai d'une heure écoulé)
    assert morte in {c["ip"] for c in etat["clients"]}
    plus_tard = T0 + 9 * 86400
    lancer(etat, regles, suivi, det=[], voisins=voisins, vues={morte: T0 + 3900, "192.168.1.128": plus_tard}, maintenant=plus_tard)    # retirée (8 jours sans DNS)
    assert morte not in {c["ip"] for c in etat["clients"]}
    lancer(etat, regles, suivi, det=[], voisins=voisins, vues={morte: T0 + 3900, "192.168.1.128": plus_tard + 8000}, maintenant=plus_tard + 8000)
    assert morte not in {c["ip"] for c in etat["clients"]}                                           # et pas rajoutée : toujours sans activité récente


# ── I4 : le plafond de règles ne bloque ni le moteur ni l'expiration ─────────────────────────────────────────────────────────
def test_i4_plafond_de_regles_refuse_l_ajout_sans_erreur_ni_changement(monkeypatch):
    etat, regles, suivi = monde()
    monkeypatch.setattr(R, "REGLES_MAX", 10)                                                          # moins que le profil (2) + de marge : on remplit
    for i in range(9):
        regles.proposer("autre", f"d{i}.example.com", 1, "faible", T0)
    res = lancer(etat, regles, suivi)
    assert res["etat_modifie"] is False and etat["clients"] == [] and [c["type"] for c in res["changements"]] == ["refus"]
    assert "règles" in res["changements"][0]["detail"]


def test_i4_le_script_expire_quand_meme_les_essais_si_l_ajout_echoue(monkeypatch, tmp_path):
    t = int(time.time())
    mod = charger_script(monkeypatch, tmp_path, {"actif": True, "ajout_auto": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]})
    donnees_tv(tmp_path, t)
    regles = R.Regles()
    from test_dnstv_auto_moteur import regle_en_essai, Rep
    rid = regle_en_essai(regles, "ad.example.com", t - R.ESSAI_S - 10)
    R.ecrire(regles, tmp_path)
    monkeypatch.setattr(A, "appliquer", lambda *a, **k: (_ for _ in ()).throw(R.ErreurRegle("trop de règles")))
    assert lancer_script(mod, lambda: Rep(), t) == 0
    assert R.charger(tmp_path).get(rid)["etat"] == "retire"                                           # l'expiration de #1954 a eu lieu malgré l'échec de l'ajout


# ── I5 : audit des changements de puits, des ignorés, et de tout `apply` ───────────────────────────────────────────────────
def test_i5_le_controleur_audite_le_puits_et_les_ignores(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    base = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}
    dnstv.ecrire_etat(base, tmp_path)
    mod.appliquer()
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto", "puits": False}], "ignores": [MAC]}, tmp_path)
    mod.regles_appliquer()
    audit = (tmp_path / "audit.log").read_text()
    assert "puits=False" in audit and "TV banc" in audit
    assert '"action": "ignore"' in audit and MAC in audit


def test_i5_apply_audite_aussi_et_apres_disable(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    mod = charger_ctl(monkeypatch, tmp_path, faux(tmp_path, "unbound-control"))
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}]}, tmp_path)
    mod.appliquer()
    mod.desactiver()
    dnstv.ecrire_etat({"actif": True, "ajout_auto": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"},
                                                                    {"ip": "192.168.1.128", "nom": "TV fb5b", "mode": "auto", "mac": MAC, "origine": "auto", "preuve": "p"}]}, tmp_path)
    assert mod.regles_appliquer() == 0                                                                # désactivé : rien n'est appliqué
    mod.appliquer()                                                                                   # une demande explicite applique ET trace
    audit = (tmp_path / "audit.log").read_text()
    assert "+ TV fb5b 192.168.1.128" in audit and '"action": "ajout_auto"' in audit

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Contrôleur root : corrections de la relecture de sécurité de la phase 2 (#1962)."""
# ruff: noqa: F811, F401  (la fixture `banc` est importée de test_ctl)
import json
import os
import shutil

from tests.test_ctl import Faux, banc, config, dropin, ecrire_config, lancer  # noqa: F401  (banc : fixture partagée)
from webfilter import ctl

TOUT_OBSERVE = {"adulte": "observe", "jeux": "observe", "phishing": "observe"}


def test_la_demande_est_consommee_des_le_debut_et_une_demande_tardive_n_est_pas_perdue(banc):
    ecrire_config(banc, config())
    (banc / "etat" / "appliquer.demande").write_text("")

    class Espion(Faux):
        def voisins(self):                                              # appelé PENDANT l'application
            assert not (banc / "etat" / "appliquer.demande").exists()
            (banc / "etat" / "appliquer.demande").write_text("")        # une nouvelle demande arrive en cours d'exécution
            return super().voisins()
    lancer(banc, Espion())
    assert (banc / "etat" / "appliquer.demande").exists()               # pas effacée à la fin : l'unité .path la reprendra


def test_json_tres_imbrique_refuse_sans_planter(banc):
    (banc / "etat" / "config.json").write_text("[" * 200000)
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and not dropin(banc).exists()


def test_dossier_d_etat_en_lien_symbolique_refuse(banc):
    (banc / "lien").symlink_to(banc / "etat")
    s = Faux()
    r = ctl.appliquer(banc / "lien", banc / "racine", dropin(banc), banc / "w.toml", systeme=s)
    assert r["statut"] == "refuse" and "dossier d'état" in r["message"] and s.appels == [] and str(banc) not in r["message"]


def test_dossier_d_etat_d_un_mauvais_proprietaire_refuse(banc):
    ecrire_config(banc, config())

    class Autre(Faux):
        def uid_service(self):
            return os.getuid() + 1
    r = lancer(banc, Autre())
    assert r["statut"] == "refuse" and "propriétaire" in r["message"] and not dropin(banc).exists()


def test_une_liste_orpheline_ne_bloque_pas(banc):
    (banc / "etat" / "listes" / "jeux" / "ancienne-source.lst").write_text("orpheline.example.net\n")      # source retirée du catalogue
    ecrire_config(banc, config())
    lancer(banc, Faux())
    t = dropin(banc).read_text()
    assert "bet.example.org" in t and "orpheline.example.net" not in t


def test_dossier_listes_en_lien_refuse(banc):
    ailleurs = banc / "ailleurs"
    ailleurs.mkdir()
    shutil.rmtree(banc / "etat" / "listes")
    (banc / "etat" / "listes").symlink_to(ailleurs)
    ecrire_config(banc, config())
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and not dropin(banc).exists()


def test_budget_global_d_octets_des_listes(banc, monkeypatch):
    ecrire_config(banc, config())
    monkeypatch.setattr(ctl, "BUDGET_OCTETS", 10)
    r = lancer(banc, Faux())
    assert r["statut"] == "refuse" and "budget" in r["message"]


def test_aucun_blocage_n_ecrit_rien_dans_unbound(banc):
    ecrire_config(banc, config(TOUT_OBSERVE))
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "inchange" and s.appels == [] and not dropin(banc).exists() and not any(a == "application" for a, _ in s.audits)
    c = json.loads((banc / "etat" / "carte.json").read_text()) if (banc / "etat" / "carte.json").exists() else {}
    assert c.get("adresses", {}) == {}


def test_plus_aucun_blocage_retire_le_dropin_et_recharge(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    assert dropin(banc).exists()
    ecrire_config(banc, config(TOUT_OBSERVE))
    s = Faux()
    r = lancer(banc, s)
    assert r["statut"] == "applique" and "aucun blocage" in r["message"] and not dropin(banc).exists() and s.appels == ["checkconf", "reload"]
    assert ("changement", "profil enfants jeux block->observe") in s.audits


def test_retrait_refuse_par_le_controle_restaure_le_dropin(banc):
    ecrire_config(banc, config())
    lancer(banc, Faux())
    avant = dropin(banc).read_bytes()
    ecrire_config(banc, config(TOUT_OBSERVE))
    r = lancer(banc, Faux(checkconf_ok=False))
    assert r["statut"] == "refuse" and dropin(banc).read_bytes() == avant

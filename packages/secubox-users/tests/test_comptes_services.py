# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Comptes dans les services modulaires (#1375)."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

import pytest

from api import comptes_services as cs

HELPER = Path(__file__).resolve().parents[1] / "sbin" / "secubox-usersctl-services"


def charge_helper():
    loader = importlib.machinery.SourceFileLoader("sus", str(HELPER))
    spec = importlib.util.spec_from_loader("sus", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


class Faux:
    """Un helper simulé : un état par service, et le journal des demandes."""

    def __init__(self, etats):
        self.etats, self.demandes = etats, []

    def __call__(self, d, delai=150):
        self.demandes.append(d)
        e = self.etats.get(d["service"], {"existe": False, "actif": None})
        if d["action"] == "etat":
            return 0, {"ok": True, "etat": e}
        if d["action"] == "creer":
            e.update(existe=True, actif=True)
        elif d["action"] == "activer":
            e["actif"] = True
        return 0, {"ok": True}


USER = {"username": "gandalf", "email": "gandalf@gk2.net"}


@pytest.fixture(autouse=True)
def propre():
    cs._cache.clear()
    yield
    cs._cache.clear()


def test_reparer_cree_ce_qui_manque_avec_un_mot_de_passe_provisoire(monkeypatch):
    f = Faux({"nextcloud": {"existe": False, "actif": None}})
    monkeypatch.setattr(cs, "helper", f)
    r = cs.agit(USER, "nextcloud", "reparer")
    assert r["etapes"] == ["creer"] and len(r["mot_de_passe"]) == 16
    cree = [d for d in f.demandes if d["action"] == "creer"][0]
    assert cree["password"] == r["mot_de_passe"]


def test_reparer_reactive_un_compte_suspendu_sans_toucher_au_mot_de_passe(monkeypatch):
    f = Faux({"peertube": {"existe": True, "actif": False}})
    monkeypatch.setattr(cs, "helper", f)
    r = cs.agit(USER, "peertube", "reparer")
    assert r["etapes"] == ["activer"] and "mot_de_passe" not in r


def test_reparer_un_compte_sain_ne_fait_rien(monkeypatch):
    monkeypatch.setattr(cs, "helper", Faux({"gitea": {"existe": True, "actif": True}}))
    assert cs.agit(USER, "gitea", "reparer")["etapes"] == ["rien à réparer"]


def test_un_mot_de_passe_fourni_n_est_jamais_renvoye(monkeypatch):
    monkeypatch.setattr(cs, "helper", Faux({}))
    r = cs.agit(USER, "email", "creer", password="le-mot-de-passe-choisi")
    assert "mot_de_passe" not in r


def test_un_refus_du_helper_remonte_son_code(monkeypatch):
    monkeypatch.setattr(cs, "helper", lambda d, delai=150: (4, {"ok": False, "erreur": "conteneur nextcloud arrêté"}))
    with pytest.raises(cs.ActionRefusee) as e:
        cs.agit(USER, "nextcloud", "creer")
    assert e.value.code == 4 and "arrêté" in e.value.detail


def test_service_et_action_inconnus_sont_refuses():
    with pytest.raises(cs.ActionRefusee) as e:
        cs.agit(USER, "jellyfin", "creer")
    assert e.value.code == 3
    with pytest.raises(cs.ActionRefusee) as e:
        cs.agit(USER, "email", "detruire-tout")
    assert e.value.code == 2


def test_l_etat_est_mis_en_cache_et_une_action_l_oublie(monkeypatch):
    f = Faux({})
    monkeypatch.setattr(cs, "helper", f)
    cs.etat(USER)
    n = len(f.demandes)
    cs.etat(USER)
    assert len(f.demandes) == n, "l'état n'a pas été servi depuis le cache"
    cs.agit(USER, "email", "creer", password="xxxxxxxxxxxx")
    cs.etat(USER)
    assert len(f.demandes) > n + 1, "une action n'a pas invalidé le cache"


def test_le_relais_de_courriel_reprend_celui_des_metriques(monkeypatch, tmp_path):
    u = tmp_path / "users.toml"
    u.write_text('[users]\nservices_par_defaut = ["email", "jellyfin"]\n')
    monkeypatch.setattr(cs, "CONF", u)
    orig = Path.read_text

    def lit(self, *a, **k):
        if str(self) == "/etc/secubox/metrics.toml":
            return '[rapport]\nsmtp_hote = "10.100.0.10"\nexpediteur = "gk2@secubox.in"\n'
        return orig(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", lit)
    c = cs.conf()
    assert c["expediteur"] == "gk2@secubox.in" and c["smtp_hote"] == "10.100.0.10"
    assert c["services_par_defaut"] == ["email"], "un service non géré a survécu"


# ── Le helper root : sa validation, sans jamais toucher un conteneur ─────────

def test_le_helper_refuse_les_demandes_mal_formees():
    h = charge_helper()
    base = {"service": "email", "action": "creer", "user": "gandalf",
            "email": "gandalf@gk2.net", "password": "assez-long-mdp"}
    h.valide(dict(base))
    for mauvais in ({"user": "Gandalf; rm -rf /"}, {"user": "-x"}, {"email": "pas une adresse"},
                    {"password": "court"}, {"password": "a\nb" * 6}, {"action": "sudo"}):
        with pytest.raises((ValueError, h.NonPrisEnCharge)):
            h.valide(dict(base, **mauvais))
    with pytest.raises(h.NonPrisEnCharge):
        h.valide(dict(base, service="jabber"))


def test_le_helper_ne_journalise_jamais_le_mot_de_passe(tmp_path, monkeypatch):
    h = charge_helper()
    monkeypatch.setattr(h, "AUDIT", tmp_path / "audit.log")
    h.audit({"service": "email", "action": "creer", "user": "gandalf",
             "password": "secret-a-ne-pas-ecrire"}, True)
    ligne = (tmp_path / "audit.log").read_text()
    assert "secret-a-ne-pas-ecrire" not in ligne and json.loads(ligne)["service"] == "email"

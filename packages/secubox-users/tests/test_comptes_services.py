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


# ── BBS (#1521) : créé comme les autres, jamais supprimé ─────────────────────

def _bbs_db(tmp_path):
    import sqlite3
    p = tmp_path / "index.db"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, handle TEXT UNIQUE, disabled_at INTEGER)")
    c.execute("INSERT INTO users (handle, disabled_at) VALUES ('Ani.skywalker', NULL), ('vieux', 12)")
    c.commit(); c.close()
    return p


def test_bbs_etat_garde_la_casse_et_voit_la_desactivation(tmp_path, monkeypatch):
    h = charge_helper()
    monkeypatch.setattr(h.Bbs, "DB", _bbs_db(tmp_path))
    b = h.Bbs()
    assert b.etat({"user": "ani.skywalker"}) == {"existe": True, "actif": True, "identifiant": "Ani.skywalker"}
    assert b.etat({"user": "vieux"})["actif"] is False
    assert b.etat({"user": "gek"}) == {"existe": False, "actif": None, "identifiant": None}


def test_bbs_creer_sous_l_utilisateur_de_la_bbs_avec_le_mot_de_passe_sur_stdin(tmp_path, monkeypatch):
    h = charge_helper()
    monkeypatch.setattr(h.Bbs, "DB", _bbs_db(tmp_path))
    vus = []
    monkeypatch.setattr(h, "lance", lambda argv, entree=None, delai=90: vus.append((argv, entree)) or (0, '{"ok": true}', ""))
    h.Bbs().creer({"user": "gek", "password": "abcd-efgh-jkmn-pqrs"})
    argv, entree = vus[0]
    # Jamais root : passwd (0600, secubox-bbs) serait réécrit au nom de root.
    assert argv[:4] == ["runuser", "-u", "secubox-bbs", "--"] and argv[-2:] == ["user-add", "gek"]
    assert entree == "abcd-efgh-jkmn-pqrs" and "abcd" not in " ".join(argv)


def test_bbs_existant_dit_existe_et_ne_se_supprime_jamais(tmp_path, monkeypatch):
    h = charge_helper()
    monkeypatch.setattr(h.Bbs, "DB", _bbs_db(tmp_path))
    with pytest.raises(h.Echec, match="existe"):          # l'appelant reprend le compte
        h.Bbs().creer({"user": "ani.skywalker", "password": "x" * 12})
    with pytest.raises(h.NonPrisEnCharge):
        h.Bbs().retirer({"user": "ani.skywalker"})
    assert "bbs" in h.ADAPTATEURS

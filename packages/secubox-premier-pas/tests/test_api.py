# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""API des faces (#1522, couche 2) : qui peut écrire, et le mot de passe ne
fait que passer."""
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "pp"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    (tmp_path / "jeton").write_text("secret-de-demarrage\n")
    (tmp_path / "jeton-local").write_text("secret-local\n")
    from api import main
    from premier_pas import remplir
    importlib.reload(remplir)
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(main.M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(main.P, "PROFILS_DIR", tmp_path / "profils")
    (tmp_path / "profils").mkdir()
    (tmp_path / "profils" / "full.toml").write_text('label = "Complet"\non = ["a", "b"]\n')
    from fastapi.testclient import TestClient
    return TestClient(main.app), main, tmp_path


J = {"X-Premier-Pas": "secret-de-demarrage"}      # code d'appairage (aussi connu du maître)
LOC = {"X-Premier-Pas": "secret-local"}           # jeton local : l'écran de la box seul


def test_sans_jeton_lecture_seule(api):
    c, _, _ = api
    assert c.get("/etat").status_code == 200
    assert c.put("/etape/nom", json={"nom": "gk3"}).status_code == 403
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers={"X-Premier-Pas": "faux"}).status_code == 403


def test_box_configuree_assistant_ferme(api):
    c, _, t = api
    (t / "fait").write_text("x")
    assert c.put("/etape/nom", json={"nom": "gk3"}, headers=J).status_code == 409


def test_mot_de_passe_jamais_en_clair(api):
    c, _, t = api
    mdp = "une-phrase-longue-et-sure"
    r = c.put("/etape/admin", json={"mot_de_passe": mdp, "confirmation": mdp}, headers=J)
    assert r.status_code == 200
    texte = (t / "pp" / "profil.toml").read_text()
    assert mdp not in texte and "$argon2" in texte
    assert r.json()["profil"]["admin"]["mot_de_passe"] == "défini"      # l'empreinte ne ressort pas


@pytest.mark.parametrize("mdp,conf", [("court", "court"), ("secubox" * 1, "secubox"),
                                       ("aaaaaaaaaaaaaa", "aaaaaaaaaaaaaa"),
                                       ("une-phrase-longue-1", "une-phrase-longue-2")])
def test_mots_de_passe_refuses(api, mdp, conf):
    c, _, _ = api
    assert c.put("/etape/admin", json={"mot_de_passe": mdp, "confirmation": conf}, headers=J).status_code == 400


def test_parcours_complet_puis_demande(api):
    c, _, t = api
    mdp = "une-phrase-longue-et-sure"
    for etape, v in [("nom", {"nom": "GK3"}), ("horloge", {"fuseau": "Europe/Paris", "ntp": True}),
                     ("admin", {"mot_de_passe": mdp, "confirmation": mdp}),
                     ("reseau", {"mode": "lan", "domaine": "ignoré.fr"}),
                     ("services", {"profil": "full"}), ("maillage", {"mode": "plus_tard"}),
                     ("majs", {"auto": True, "heure": "03:00"})]:
        r = c.put(f"/etape/{etape}", json=v, headers=J)
        assert r.status_code == 200, (etape, r.text)
    e = r.json()
    assert e["complet"] and e["profil"]["box"]["nom"] == "gk3"
    assert "domaine" not in e["profil"]["reseau"]                        # LAN seul
    assert c.post("/appliquer", headers=J).status_code == 403      # le code ne décide pas
    assert c.post("/appliquer", headers=LOC).status_code == 200
    assert (t / "pp" / "demande").exists()


def test_appliquer_incomplet_refuse(api):
    c, _, _ = api
    r = c.post("/appliquer", headers=LOC)
    assert r.status_code == 409 and "Nom" in r.json()["detail"]


def test_champ_inconnu_refuse(api):
    c, _, _ = api
    assert c.put("/etape/nom", json={"nom": "gk3", "root": "x"}, headers=J).status_code == 400


def test_choix_liste_les_profils(api):
    c, _, _ = api
    assert c.get("/choix").json()["profils"][0] == {"id": "full", "libelle": "Complet", "modules": 2}


MDP = "une-phrase-longue-et-sure"
PARCOURS = [("nom", {"nom": "gk3"}), ("horloge", {"fuseau": "Europe/Paris", "ntp": True}),
            ("admin", {"mot_de_passe": MDP, "confirmation": MDP}), ("reseau", {"mode": "lan"}),
            ("services", {"profil": "full"}), ("maillage", {"mode": "plus_tard"}),
            ("majs", {"auto": True, "heure": "03:00"})]


def _remplit(c, h=J):
    for etape, v in PARCOURS:
        assert c.put(f"/etape/{etape}", json=v, headers=h).status_code == 200


def test_proposition_le_maitre_ne_peut_pas_accepter(api):
    c, _, t = api
    _remplit(c)
    r = c.post("/proposition", json={"par": "gk2", "mode": "proposer"}, headers=J)
    assert r.status_code == 200 and r.json()["statut"] == "en_attente"
    assert not (t / "pp" / "demande").exists()                       # rien sans l'utilisateur
    assert c.post("/proposition/accepter", headers=J).status_code == 403
    assert c.get("/etat").json()["proposition"]["par"] == "gk2"
    assert c.post("/proposition/accepter", headers=LOC).json()["statut"] == "acceptee"
    assert (t / "pp" / "demande").exists()


def test_proposition_refusee(api):
    c, _, t = api
    _remplit(c)
    c.post("/proposition", json={"par": "gk2"}, headers=J)
    assert c.post("/proposition/refuser", headers=LOC).json()["statut"] == "refusee"
    assert not (t / "pp" / "demande").exists()
    assert c.post("/proposition/accepter", headers=LOC).status_code == 409


def test_forcer_applique_et_le_dit(api):
    c, _, t = api
    _remplit(c)
    r = c.post("/proposition", json={"par": "gk2", "mode": "forcer"}, headers=J)
    assert r.json()["statut"] == "forcee" and (t / "pp" / "demande").exists()
    assert c.get("/etat").json()["proposition"]["mode"] == "forcer"   # l'écran l'annonce


def test_code_seulement_pour_l_ecran(api):
    c, _, _ = api
    assert c.get("/code", headers=J).status_code == 403
    assert c.get("/code", headers=LOC).json()["code"] == "secret-de-demarrage"


def test_fuseau_inconnu_refuse_et_liste_fournie(api):
    c, _, _ = api
    assert "Europe/Paris" in c.get("/choix").json()["fuseaux"]
    r = c.put("/etape/horloge", json={"fuseau": "Europe/Pariss", "ntp": True}, headers=J)
    assert r.status_code != 200 and "Fuseau inconnu" in r.json()["detail"]
    assert c.put("/etape/horloge", json={"fuseau": "Europe/Paris", "ntp": True}, headers=J).status_code == 200

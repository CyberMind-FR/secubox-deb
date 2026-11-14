# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tâche 2 (#3583) : préférences en double tampon et configuration fixe."""
import tomllib

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api import reglages
from api.main import app
from secubox_core.auth import require_jwt


@pytest.fixture(autouse=True)
def etat(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    monkeypatch.setenv("SECUBOX_AI_CONF", str(tmp_path / "ai.toml"))
    return tmp_path


def test_defauts_sans_fichier():
    assert reglages.lire_prefs() == reglages.DEFAUTS
    assert reglages.etat_prefs()["erreur"] is None


def test_contexte_zero_accepte_et_65536_refuse():
    assert reglages.valider({"moteur": {"contexte": 0}})["moteur"]["contexte"] == 0
    with pytest.raises(HTTPException) as e:
        reglages.valider({"moteur": {"contexte": 65536}})
    assert e.value.status_code == 422


def test_cle_inconnue_422():
    for mauvais in ({"moteur": {"inconnu": 1}}, {"inconnue": {"a": 1}}):
        with pytest.raises(HTTPException) as e:
            reglages.valider(mauvais)
        assert e.value.status_code == 422


def test_ecriture_relecture_sans_tmp(etat):
    prefs = reglages.valider({"menaces": {"resume_auto_min": 5}, "outils": {"sources_max_jetons": 2000}})
    reglages.ecrire_prefs(prefs)
    assert reglages.lire_prefs()["menaces"]["resume_auto_min"] == 5
    assert not (etat / "preferences.tmp").exists()


def test_ecriture_atomique_pas_de_fichier_partiel(etat, monkeypatch):
    reglages.ecrire_prefs(reglages.valider({"memoire": {"caracteres": 2000}}))
    avant = (etat / "preferences.toml").read_text()

    def casse(_texte):
        raise tomllib.TOMLDecodeError("illisible")

    monkeypatch.setattr(reglages.tomllib, "loads", casse)
    with pytest.raises(tomllib.TOMLDecodeError):
        reglages.ecrire_prefs(reglages.DEFAUTS)
    assert (etat / "preferences.toml").read_text() == avant
    assert not (etat / "preferences.tmp").exists()


def test_fichier_corrompu_rend_les_defauts_et_le_dit(etat):
    (etat / "preferences.toml").write_text("[moteur\ncontexte = = 3", encoding="utf-8")
    assert reglages.lire_prefs() == reglages.DEFAUTS
    assert reglages.etat_prefs()["erreur"]


def test_status_signale_l_erreur(etat):
    (etat / "preferences.toml").write_text("n'importe quoi", encoding="utf-8")
    app.dependency_overrides[require_jwt] = lambda: {"sub": "t"}
    try:
        r = TestClient(app).get("/status")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 200 and r.json()["preferences"]["erreur"]


def test_config_fixe(etat):
    assert reglages.config()["gk2"]["menaces_url"] == "https://admin.gk2.secubox.in/api/v1"
    (etat / "ai.toml").write_text('[distant]\nurl = "https://x.example/v1"\n', encoding="utf-8")
    cfg = reglages.config()
    assert cfg["distant"]["url"] == "https://x.example/v1" and "sources_url" in cfg["gk2"]
    assert cfg["moteur_local"]["modele"]


def test_routes_preferences_gardees_et_fonctionnelles():
    c = TestClient(app)
    assert c.get("/preferences").status_code in (401, 403)
    app.dependency_overrides[require_jwt] = lambda: {"sub": "t"}
    try:
        assert c.put("/preferences", json={"moteur": {"contexte": 65536}}).status_code == 422
        assert c.put("/preferences", json={"moteur": {"contexte": 8192}}).status_code == 200
        assert c.get("/preferences").json()["preferences"]["moteur"]["contexte"] == 8192
    finally:
        app.dependency_overrides.clear()


def test_valeurs_invalides_du_fichier_retombent_sur_les_defauts(etat):
    (etat / "preferences.toml").write_text(
        '[moteur]\nthreads = "x"\ncontexte = 999999\nbackend = "x"\nnice = 5\n[memoire]\ncaracteres = 2000\n',
        encoding="utf-8")
    prefs = reglages.lire_prefs()
    assert prefs["moteur"]["threads"] == reglages.DEFAUTS["moteur"]["threads"]
    assert prefs["moteur"]["contexte"] == reglages.DEFAUTS["moteur"]["contexte"]
    assert prefs["moteur"]["backend"] == "cpu"
    assert prefs["moteur"]["nice"] == 5 and prefs["memoire"]["caracteres"] == 2000
    erreur = reglages.etat_prefs()["erreur"]
    assert "moteur.threads" in erreur and "moteur.contexte" in erreur and "moteur.backend" in erreur
    assert "moteur.nice" not in erreur and "999999" not in erreur

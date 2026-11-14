# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mémoire et Historique (#3583)."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import memoire, taches
from api.main import app


@pytest.fixture
def cli(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_crochet_historique_branche():
    assert taches.HISTORIQUE_AJOUTER is memoire.historique_ajouter


def test_fts_sans_accents(cli):
    memoire.memoire_ajouter("note", "Fusée", "Le vol d’essai de la fusée a eu lieu hier.")
    assert memoire.memoire_chercher("essai")[0]["titre"] == "Fusée"
    assert memoire.memoire_chercher("fusee")        # sans accent
    assert memoire.memoire_chercher("zzzzqq") == []


def test_correction_en_tete_et_budget(cli):
    memoire.memoire_ajouter("note", "Banale", "la capitale du pays est Lyon Lyon Lyon Lyon")
    cli.post("/memoire/corrections", json={"question": "capitale ?", "bonne": "la capitale du pays est Paris"})
    res = memoire.memoire_chercher("capitale pays")
    assert res[0]["titre"].startswith("Correction")
    assert memoire.memoire_chercher("capitale pays", budget_car=10) == []
    memoire.memoire_chercher("capitale pays", compter=True)
    assert all(s["utilise"] == 1 for s in cli.get("/memoire").json()["souvenirs"])


def test_bloc_et_declencheur():
    b = memoire.bloc_memoire([{"titre": "T", "genre": "note", "repere": "", "texte": "é"}])
    assert b.startswith("<donnees>") and "é" in b
    assert memoire.DECLENCHEUR_MEMOIRE.match("Retiens que le code est 42").group(2) == "le code est 42"
    assert "DONNÉES" in memoire.CONSIGNE_MEMOIRE


def test_tout_oublier_exige_oublier(cli):
    memoire.memoire_ajouter("note", "a", "b")
    assert cli.post("/memoire/tout-oublier", json={"confirmation": "oui"}).status_code == 422
    assert len(cli.get("/memoire").json()["souvenirs"]) == 1
    assert cli.post("/memoire/tout-oublier", json={"confirmation": "OUBLIER"}).status_code == 200
    assert cli.get("/memoire").json()["souvenirs"] == []
    assert memoire.memoire_chercher("b b") == []


def test_crud_et_routes(cli):
    i = cli.post("/memoire/notes", json={"titre": "T", "texte": "alpha beta"}).json()["id"]
    assert cli.get(f"/memoire/{i}").json()["texte"] == "alpha beta"
    assert cli.get("/memoire/chercher", params={"q": "alpha"}).json()["passages"]
    assert cli.put(f"/memoire/{i}", json={"titre": "T2", "texte": "gamma delta"}).status_code == 200
    assert not cli.get("/memoire/chercher", params={"q": "alpha"}).json()["passages"]
    assert cli.get("/memoire/chercher", params={"q": "gamma"}).json()["passages"]
    assert cli.post("/memoire/notes", json={"titre": "", "texte": "x"}).status_code == 422
    assert cli.get("/memoire", params={"genre": "reponse"}).json()["souvenirs"] == []
    assert cli.delete(f"/memoire/{i}").status_code == 200
    assert cli.delete(f"/memoire/{i}").status_code == 404
    assert cli.get(f"/memoire/{i}").status_code == 404
    r = cli.post("/memoire/reponses", json={"question": "Q ?", "reponse": "R", "sources": ["http://x.y", "ftp://z", "pas"]})
    assert cli.get(f"/memoire/{r.json()['id']}").json()["source"] == "http://x.y"


def test_reglage(cli):
    assert cli.put("/memoire-reglage", json={"actif": False}).json() == {"actif": False}
    assert cli.get("/memoire").json()["actif"] is False


def test_export_puis_import_meme_nombre(cli, tmp_path, monkeypatch):
    memoire.memoire_ajouter("note", "a", "texte un")
    memoire.memoire_ajouter("reponse", "b", "texte deux", "http://s", 1)
    exp = cli.get("/memoire-export")
    assert exp.json()["format"] == "secubox-ai-memoire/1" and "attachment" in exp.headers["content-disposition"]
    cli.post("/memoire/tout-oublier", json={"confirmation": "OUBLIER"})
    assert cli.post("/memoire-import", json=exp.json()).json() == {"importes": 2}
    assert len(cli.get("/memoire").json()["souvenirs"]) == 2
    assert memoire.memoire_chercher("deux")


def test_import_fichier_poc_gk0(cli):
    poc = {"format": "secubox-ai-memoire/1", "souvenirs": [
        {"genre": "note", "titre": "Correction : « q »", "texte": "À la question, la bonne réponse est : Paris",
         "source": "", "priorite": 1, "cree": 1762900000.5},
        {"genre": "document", "titre": "Doc", "texte": "contenu du document", "source": "https://x", "priorite": 0,
         "cree": 1762900001.0}]}
    assert cli.post("/memoire-import", json=poc).json() == {"importes": 2}
    assert memoire.memoire_chercher("bonne reponse")[0]["genre"] == "note"


@pytest.mark.parametrize("mauvais", [
    {"genre": "inconnu", "titre": "t", "texte": "x"}, {"genre": "note", "titre": 5, "texte": "x"},
    {"genre": "note", "titre": "t" * 201, "texte": "x"}, {"genre": "note", "titre": "t", "texte": ""},
    {"genre": "note", "titre": "t", "texte": "x", "source": "s" * 501},
    {"genre": "note", "titre": "t", "texte": "x", "priorite": "haute"}, "pas un objet"])
def test_import_invalide_422_sans_ecriture(cli, mauvais):
    bon = {"genre": "note", "titre": "ok", "texte": "bon"}
    rep = cli.post("/memoire-import", json={"format": "secubox-ai-memoire/1", "souvenirs": [bon, mauvais]})
    assert rep.status_code == 422
    assert cli.get("/memoire").json()["souvenirs"] == []


def test_import_format_et_taille(cli):
    assert cli.post("/memoire-import", json={"format": "autre", "souvenirs": []}).status_code == 422
    assert cli.post("/memoire-import", json={"format": "secubox-ai-memoire/1", "souvenirs": "x"}).status_code == 422
    trop = [{"genre": "note", "titre": "t", "texte": "x"}] * 5001
    assert cli.post("/memoire-import", json={"format": "secubox-ai-memoire/1", "souvenirs": trop}).status_code == 422


def test_historique(cli):
    memoire.historique_ajouter("dialogue", "Qui est là ?", "Moi.", ["http://a", "http://b"])
    memoire.historique_ajouter("analyse", "Menaces", "rien")
    liste = cli.get("/historique").json()["historique"]
    assert [x["genre"] for x in liste] == ["analyse", "dialogue"]
    assert [x["titre"] for x in cli.get("/historique", params={"genre": "dialogue"}).json()["historique"]] == ["Qui est là ?"]
    assert len(cli.get("/historique", params={"q": "Moi"}).json()["historique"]) == 1
    assert cli.get("/historique", params={"q": "%"}).json()["historique"] == []   # joker neutralisé
    i = [x["id"] for x in liste if x["genre"] == "dialogue"][0]
    assert cli.get(f"/historique/{i}").json()["sources"] == ["http://a", "http://b"]
    m = cli.post(f"/historique/{i}/memoriser").json()["id"]
    mem = cli.get(f"/memoire/{m}").json()
    assert mem["genre"] == "reponse" and "Question : Qui est là ?" in mem["texte"] and mem["source"] == "http://a · http://b"
    assert cli.delete(f"/historique/{i}").status_code == 200
    assert cli.get(f"/historique/{i}").status_code == 404
    assert cli.delete(f"/historique/{i}").status_code == 404
    assert cli.post(f"/historique/{i}/memoriser").status_code == 404


def test_historique_borne_a_2000(cli, monkeypatch):
    monkeypatch.setattr(memoire, "HISTORIQUE_MAX", 3)
    for n in range(5):
        memoire.historique_ajouter("dialogue", f"t{n}", "x")
    assert [x["titre"] for x in cli.get("/historique").json()["historique"]] == ["t4", "t3", "t2"]


@pytest.mark.asyncio
async def test_tache_finie_dans_l_historique(cli):
    taches.TACHES.clear()
    t = taches.nouvelle_tache("document", "Mon doc")

    async def travail():
        taches.finir(t, "fini", "le résultat")
    taches.lancer_tache(t, travail(), 5)
    await taches.TACHES[t]["_tache"]
    taches.TACHES.clear()
    h = cli.get("/historique").json()["historique"]
    assert any("Mon doc" in x["titre"] for x in h)


def test_historique_echec_base_sans_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "fichier"))
    (tmp_path / "fichier").write_text("pas un dossier")
    memoire.historique_ajouter("dialogue", "t", "x")   # ne lève pas


def test_journal_sans_contenu(cli, caplog):
    caplog.set_level("DEBUG")
    memoire.memoire_ajouter("note", "TitreSecret", "ContenuSecret")
    memoire.historique_ajouter("dialogue", "QuestionSecrete", "ReponseSecrete")
    cli.get("/memoire/chercher", params={"q": "ContenuSecret"})
    assert "Secret" not in caplog.text


def test_routes_refusees_sans_jeton(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    c = TestClient(app)
    for m, u in (("get", "/memoire"), ("get", "/historique"), ("get", "/memoire-export")):
        assert getattr(c, m)(u).status_code in (401, 403)


def test_base_en_wal(cli, tmp_path):
    memoire.memoire_ajouter("note", "a", "b")
    assert sqlite3.connect(tmp_path / "memoire.db").execute("PRAGMA journal_mode").fetchone()[0] == "wal"

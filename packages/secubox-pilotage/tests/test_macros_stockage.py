# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import sqlite3

import pytest

from pilotage import stockage as st
from pilotage.macros import LIVREES
from pilotage.stockage import StockageSqlite
from outils import GK5, Horloge, P

R = {"type": "releve", "duree_s": 60, "nom": "avant"}
A = {"type": "action", "action": "maj-paquets"}
CIBLES = [{"cle": "maillage:gk7", "nom": "gk7"}, {"cle": "maillage:gk6", "nom": "gk6"}]


@pytest.fixture
def s(tmp_path):
    return StockageSqlite(tmp_path / "pilotage", horloge=Horloge())


def test_tables_creees_sur_une_base_existante(tmp_path):
    d = tmp_path / "pilotage"
    d.mkdir()
    cx = sqlite3.connect(d / "pilotage.db")
    cx.execute("CREATE TABLE boites(cle TEXT PRIMARY KEY, nom TEXT NOT NULL, adresse TEXT NOT NULL, reseau TEXT NOT NULL, client TEXT, "
               "abonnement TEXT, agent_version TEXT NOT NULL DEFAULT '', vu_le INTEGER NOT NULL, inventaire_le INTEGER, "
               "inventaire_partiel INTEGER NOT NULL DEFAULT 0, boot_id TEXT NOT NULL DEFAULT '')")
    cx.execute("INSERT INTO boites(cle,nom,adresse,reseau,vu_le) VALUES('maillage:gk5','gk5','10.10.0.5','maillage',1)")
    cx.commit()
    cx.close()
    s = StockageSqlite(d)
    tables = {r[0] for r in sqlite3.connect(d / "pilotage.db").execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"macros", "executions", "execution_etapes", "execution_releves"} <= tables
    assert s.boite("maillage:gk5")["nom"] == "gk5"


def test_livrees_reecrites_et_non_modifiables(s):
    s.macros_livrees_installer(LIVREES)
    s.macros_livrees_installer(LIVREES)
    assert [m["id"] for m in s.macros()][:4] == [x["id"] for x in LIVREES]
    assert len(s.macros()) == 4 and all(m["livree"] for m in s.macros())
    assert s.macro_maj("livree:diagnostic-complet", "x", [], [], None) is False
    assert s.macro_supprimer("livree:retour-en-local") is False
    assert s.macro_lire("livree:diagnostic-complet")["nom"] == "Diagnostic complet"


def test_macro_creer_lire_maj_supprimer(s):
    s.macros_livrees_installer(LIVREES)
    i = s.macro_creer("Ma macro", [R, A], CIBLES, {"quotidien": "03:30"}, "alice")
    assert i.startswith("m-") and len(i) == 14
    m = s.macro_lire(i)
    assert m["nom"] == "Ma macro" and m["etapes"] == [R, A] and m["cibles"] == CIBLES and m["programmation"] == {"quotidien": "03:30"}
    assert m["livree"] is False and m["auteur"] == "alice"
    assert [x["id"] for x in s.macros_programmees()] == [i]
    assert s.macros()[-1]["id"] == i                               # les livrées d'abord
    assert s.macro_maj(i, "Autre", [R], [], None) is True
    m = s.macro_lire(i)
    assert m["nom"] == "Autre" and m["etapes"] == [R] and m["programmation"] is None and m["cree_le"] <= m["maj_le"]
    assert s.macros_programmees() == []
    assert s.macro_maj("m-000000000000", "x", [], [], None) is False
    assert s.macro_supprimer(i) is True and s.macro_lire(i) is None and s.macro_supprimer(i) is False


def test_donnees_non_json_refusees(s):
    with pytest.raises((TypeError, ValueError)):
        s.macro_creer("x", [{"type": object()}], [], None, "a")
    assert s.macros() == []


def test_plafond_des_macros(s, monkeypatch):
    monkeypatch.setattr(st, "MACROS_MAX", 3)
    s.macros_livrees_installer(LIVREES)                           # les livrées ne comptent pas
    for k in range(3):
        assert s.macro_creer(f"m{k}", [R], [], None, "a")
    assert s.macro_creer("trop", [R], [], None, "a") is None


def test_execution_lignes_en_attente_puis_clore(s):
    i = s.execution_creer("m-1", "M", CIBLES, [R, A], "alice")
    e = s.execution(i)
    assert e["etat"] == "en_cours" and e["cibles"] == CIBLES and len(e["etapes"]) == 4
    assert {x["etat"] for x in e["etapes"]} == {"en_attente"}
    s.etape_noter(i, "maillage:gk7", 0, "en_cours")
    s.etape_noter(i, "maillage:gk7", 0, "ecart", {"nouveaux": ["x"]})
    assert s.etapes_clore(i, "non_lancee") == 3
    e = s.execution(i)
    assert [x["etat"] for x in e["etapes"]] == ["ecart", "non_lancee", "non_lancee", "non_lancee"]
    assert [x["box"] for x in e["etapes"]] == ["maillage:gk7"] * 2 + ["maillage:gk6"] * 2
    premiere = e["etapes"][0]
    assert premiere["resultat"] == {"nouveaux": ["x"]} and premiere["debut"] is not None and premiere["fin"] is not None
    assert e["etapes"][1]["debut"] is None
    assert s.execution(999) is None


def test_clore_une_seule_box(s):
    i = s.execution_creer("m-1", "M", CIBLES, [R, A], "alice")
    assert s.etapes_clore(i, "non_lancee", "maillage:gk6") == 2
    assert [x["etat"] for x in s.execution(i)["etapes"]] == ["en_attente"] * 2 + ["non_lancee"] * 2


def test_execution_finir_et_liste(s):
    a = s.execution_creer("m-1", "M", CIBLES, [R], "alice")
    b = s.execution_creer("m-1", "M", CIBLES, [R], "bob")
    s.execution_finir(a, "ecart", "un service en échec")
    assert [x["id"] for x in s.executions()] == [b, a]
    assert "etapes" not in s.executions()[0]
    e = s.execution(a)
    assert e["etat"] == "ecart" and e["raison"] == "un service en échec" and e["fin"] is not None


def test_interrompre_au_demarrage(s):
    vivante = s.execution_creer("m-1", "M", CIBLES, [R, A], "alice")
    finie = s.execution_creer("m-1", "M", CIBLES, [R], "alice")
    s.etape_noter(vivante, "maillage:gk7", 0, "ok")
    s.etape_noter(vivante, "maillage:gk7", 1, "en_cours")
    s.execution_finir(finie, "terminee")
    changees = s.executions_interrompre()
    assert [x["id"] for x in changees] == [vivante]
    assert s.execution(vivante)["etat"] == "interrompue" and s.execution(finie)["etat"] == "terminee"
    assert [x["etat"] for x in s.execution(vivante)["etapes"]] == ["ok", "interrompue", "interrompue", "interrompue"]
    assert s.executions_interrompre() == []


def test_executions_bornees(s, monkeypatch):
    monkeypatch.setattr(st, "EXECUTIONS_MAX", 3)
    premiere = s.execution_creer("m-1", "M", CIBLES, [R], "a")
    s.releve_ranger(premiere, "maillage:gk7", "avant", {"x": 1})
    for _ in range(3):
        s.execution_creer("m-1", "M", CIBLES, [R], "a")
    assert s.execution(premiere) is None
    assert len(s.executions(100)) == 3
    cx = sqlite3.connect(s.db)
    assert cx.execute("SELECT COUNT(*) FROM execution_etapes WHERE execution_id=?", (premiere,)).fetchone()[0] == 0
    assert cx.execute("SELECT COUNT(*) FROM execution_releves WHERE execution_id=?", (premiere,)).fetchone()[0] == 0


def test_programmee_depuis(s):
    h = s.horloge
    s.execution_creer("m-1", "M", CIBLES, [R], "alice")
    assert s.execution_programmee_depuis("m-1", int(h.t) - 10) is False        # autre acteur
    s.execution_creer("m-1", "M", CIBLES, [R], "planificateur")
    assert s.execution_programmee_depuis("m-1", int(h.t)) is True
    assert s.execution_programmee_depuis("m-1", int(h.t) + 1) is False
    assert s.execution_programmee_depuis("m-2", 0) is False


def test_releves_par_execution_et_box(s):
    i = s.execution_creer("m-1", "M", CIBLES, [R], "a")
    s.releve_ranger(i, "maillage:gk7", "avant", {"a": 1})
    s.releve_ranger(i, "maillage:gk7", "avant", {"a": 2})
    s.releve_ranger(i, "maillage:gk7", "apres", {"a": 3})
    s.releve_ranger(i, "maillage:gk6", "avant", {"a": 9})
    assert s.releves_execution(i, "maillage:gk7") == {"avant": {"a": 2}, "apres": {"a": 3}}
    assert s.releves_execution(i, "maillage:gk6") == {"avant": {"a": 9}}
    assert s.releves_execution(i, "maillage:gk5") == {}


def test_resumes_porte_le_modele(s):
    s.vu(GK5, {})
    assert s.resumes()[0]["modele"] is None
    s.inventaire_enregistrer(GK5, {"results": [{"path": "Device.", "params": {P + "DeviceInfo.ModelName": "Globalscale MOCHAbin"}}]})
    assert s.resumes()[0]["modele"] == "Globalscale MOCHAbin"
    s.inventaire_enregistrer(GK5, {"results": [{"path": "Device.", "params": {P + "DeviceInfo.ModelName": "x" * 300}}]})
    assert s.resumes()[0]["modele"] == "x" * 120
    s.inventaire_enregistrer(GK5, {"results": [{"path": "Device.", "params": {P + "DeviceInfo.ModelName": 7}}]})
    assert s.resumes()[0]["modele"] is None

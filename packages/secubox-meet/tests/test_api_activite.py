# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3182 — API : réunions, connexions, statistiques, clore. Administrateur seulement ; l'historique vient de activite.db."""
import json

import pytest

import test_api
from test_activite import FIREFOX, GANDALF, SALLE, T0, actif, debut, fin, sans_connexion

from api import activite as A

M = test_api.M
cli = test_api.cli          # fixture partagée avec test_api (faux meetctl, faux jetons)


@pytest.fixture
def base(monkeypatch, tmp_path):
    chemin = tmp_path / "activite.db"
    cx = A.ouvrir(chemin)
    A.comptes(cx, json.dumps([{"sub": GANDALF, "pseudo": "gandalf"}]))
    A.collecter(cx, [debut(T0, "PA_1"), actif(T0 + 1, "PA_1", client=FIREFOX), fin(T0 + 61, "PA_1"),
                     debut(T0 + 100, "PA_2"), fin(T0 + 101, "PA_2", "SIGNAL_SOURCE_CLOSE"), sans_connexion(T0 + 101, "PA_2")])
    cx.close()
    monkeypatch.setattr(M, "ACTIVITE_DB", chemin)
    monkeypatch.setattr(M.time, "time", lambda: T0 + 200)
    M._activite_cache.clear()
    return chemin


ROUTES = ["/reunions", "/connexions", "/stats"]


@pytest.mark.parametrize("route", ROUTES)
def test_lecture_reservee_a_l_administrateur(cli, base, route):
    assert cli.get(route, jwt=False, lecture=True).status_code == 401
    assert cli.get(route, jwt=True).status_code == 200


def test_reunions_delegue_et_met_en_cache(cli, base):
    cli.sorties["reunions"] = json.dumps({"reunions": [{"salle": SALLE, "slug": "gii"}], "releve": T0})
    r1, r2 = cli.get("/reunions", jwt=True), cli.get("/reunions", jwt=True)
    assert r1.json()["reunions"][0]["slug"] == "gii" and r2.status_code == 200
    assert cli.appels.count(("reunions",)) == 1


def test_connexions_direct_et_historique_filtrable(cli, base):
    cli.sorties["en-direct"] = json.dumps({"salles": [{"salle": SALLE, "participants": []}], "releve": T0})
    d = cli.get("/connexions", jwt=True).json()
    assert d["en_direct"]["salles"][0]["salle"] == SALLE
    assert [(h["sid"], h["issue"], h["participant"]) for h in d["historique"]] == [("PA_2", "echec", "gandalf"),
                                                                                  ("PA_1", "aboutie", "gandalf")]
    d = cli.get("/connexions?issue=echec", jwt=True).json()
    assert [h["sid"] for h in d["historique"]] == ["PA_2"]
    assert cli.get(f"/connexions?salle={SALLE}&jours=7", jwt=True).status_code == 200
    assert cli.get("/connexions?jours=90", jwt=True).status_code == 422
    assert cli.get("/connexions?issue=autre", jwt=True).status_code == 422


def test_connexions_direct_indisponible_n_empeche_pas_l_historique(cli, base, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, json.dumps({"success": False, "error": "LiveKit injoignable"}), ""))
    d = cli.get("/connexions", jwt=True).json()
    assert d["en_direct"] is None and "LiveKit injoignable" in d["erreur_direct"] and len(d["historique"]) == 2


def test_stats_periodes(cli, base):
    d = cli.get("/stats?periode=7", jwt=True).json()
    assert d["sessions_abouties"] == 1 and d["echecs"] == 1 and d["secondes"] == 60
    assert cli.get("/stats?periode=365", jwt=True).status_code == 200
    assert cli.get("/stats?periode=12", jwt=True).status_code == 422


def test_stats_sans_base_rend_des_zeros(cli, monkeypatch, tmp_path):
    monkeypatch.setattr(M, "ACTIVITE_DB", tmp_path / "absente.db")
    d = cli.get("/stats?periode=30", jwt=True).json()
    assert d["sessions"] == 0 and d["secondes"] == 0 and len(d["par_jour"]) == 30
    assert not (tmp_path / "absente.db").exists()


def test_clore_exige_confirmation_et_nom_valide(cli, base):
    assert cli.post("/clore", json={"salle": SALLE, "confirmer": "meet"}, jwt=False).status_code == 401
    assert cli.post("/clore", json={"salle": SALLE}, jwt=True).status_code == 400
    assert cli.post("/clore", json={"salle": "../x", "confirmer": "meet"}, jwt=True).status_code == 400
    assert not cli.appels
    r = cli.post("/clore", json={"salle": SALLE, "confirmer": "meet"}, jwt=True)
    assert r.status_code == 200 and cli.appels[-1] == ("clore", SALLE, "admin")         # l'auteur part à l'audit


def test_clore_echec_du_controleur(cli, base, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, json.dumps({"success": False, "error": "salle inconnue"}), ""))
    r = cli.post("/clore", json={"salle": SALLE, "confirmer": "meet"}, jwt=True)
    assert r.status_code == 502 and "salle inconnue" in r.json()["detail"]

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3946 — monter les routes d'ingestion mitm n'écrit rien : la base naît au premier événement."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secubox_core.mitm_ingest import mount_ingest_routes


def _client(db):
    app = FastAPI()
    mount_ingest_routes(app, endpoint_path="/event", db_path=db, kind="essai")
    return TestClient(app)


def test_le_montage_ne_cree_ni_dossier_ni_base(tmp_path):
    db = tmp_path / "etat" / "mitm.db"
    _client(db)
    assert not db.parent.exists()


def test_le_premier_evenement_cree_la_base_et_se_relit(tmp_path):
    db = tmp_path / "etat" / "mitm.db"
    c = _client(db)
    assert c.post("/event", json={"ts_ms": 101, "client_mac_hash": "a" * 16}).json() == {"ok": True, "kind": "essai"}
    assert db.is_file()
    r = c.get("/mitm-events").json()
    assert r["count"] == 1 and r["events"][0]["mac_hash"] == "a" * 16


@pytest.mark.parametrize("route", ["/mitm-events", "/mitm-events/stats"])
def test_une_lecture_avant_tout_evenement_rend_zero_sans_erreur_ni_fichier(tmp_path, route):
    db = tmp_path / "etat" / "mitm.db"
    r = _client(db).get(route).json()
    assert r["count"] == 0 and "error" not in r
    assert not db.parent.exists()


def test_une_base_retiree_en_marche_est_recreee(tmp_path):
    db = tmp_path / "etat" / "mitm.db"
    c = _client(db)
    c.post("/event", json={"ts_ms": 101})
    db.unlink()
    assert c.post("/event", json={"ts_ms": 103}).json()["ok"] is True
    assert c.get("/mitm-events").json()["count"] == 1


def test_un_dossier_impossible_a_creer_ne_tombe_qu_a_l_ecriture(tmp_path):
    barrage = tmp_path / "fichier"
    barrage.write_text("")
    c = _client(barrage / "etat" / "mitm.db")
    assert c.post("/event", json={"ts_ms": 101}).json() == {"ok": False, "error": "store_failed"}

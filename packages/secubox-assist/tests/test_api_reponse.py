# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1711 : une demande d'un autre nœud est visible, attribuée, et on y répond
en un geste — jamais à sa propre demande, jamais à une demande échue."""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[2].parent / "common")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-dual-test-journal.db")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from annuaire.assist_match import author_prefix  # noqa: E402
from api import main  # noqa: E402

GK2 = "did:plc:04637c9028cb4e43ada5fabe680c457d"
GK3 = "did:plc:8722bea61ea8618657e7199e00a20ff2"


def _demande(auteur, motif, il_y_a_s=60, ttl=3600):
    cree = datetime.fromtimestamp(datetime.now(timezone.utc).timestamp() - il_y_a_s, timezone.utc)
    rid = author_prefix(auteur) + "-" + motif.encode().hex()[:16].ljust(16, "0")
    return {"op": "assist_request_open", "author": auteur, "payload": {
        "req_id": rid, "issued_by": auteur, "tags": ["test"], "scope": None,
        "ttl_s": ttl, "created_at": cree.isoformat(), "reason": motif}}


def _noeud(did, nom):
    return {"op": "node_publish", "author": did, "payload": {"did": did, "boxname": nom}}


@pytest.fixture
def c(monkeypatch):
    entrees = [_noeud(GK3, "gk3"), _noeud(GK2, "gk2"),
               _demande(GK3, "plz"), _demande(GK2, "la mienne"),
               _demande(GK3, "échue", il_y_a_s=7200, ttl=3600)]
    appels = []

    def ctl(*args):
        appels.append(args)
        if args[0] == "offer":
            return {"offer_id": author_prefix(GK2) + "-0011223344556677"}
        if args[0] == "match-accept":
            return {"match_id": "m-1"}
        return {}
    monkeypatch.setattr(main, "_entries", lambda: entrees)
    monkeypatch.setattr(main, "_self_did", lambda: GK2)
    monkeypatch.setattr(main, "_ctl", ctl)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(main.app), appels
    main.app.dependency_overrides.clear()


def test_la_demande_de_gk3_est_visible_et_attribuee(c):
    cli, _ = c
    r = cli.get("/requests/open").json()
    par_motif = {q["reason"]: q for q in r}
    assert set(par_motif) == {"plz", "la mienne"}          # l'échue n'y est pas
    assert par_motif["plz"]["noeud"] == "gk3" and par_motif["plz"]["de_moi"] is False
    assert par_motif["la mienne"]["de_moi"] is True


def test_repondre_publie_une_offre_aux_memes_etiquettes_puis_accepte(c):
    cli, appels = c
    rid = next(q["req_id"] for q in cli.get("/requests/open").json() if q["reason"] == "plz")
    r = cli.post("/request/answer", json={"req_id": rid})
    assert r.status_code == 200, r.text
    assert r.json()["noeud"] == "gk3" and r.json()["match_id"] == "m-1"
    assert appels[0][0] == "offer" and "test" in appels[0]
    assert appels[1] == ("match-accept", author_prefix(GK2) + "-0011223344556677", rid, "offer")


def test_on_ne_repond_pas_a_sa_propre_demande(c):
    cli, appels = c
    rid = next(q["req_id"] for q in cli.get("/requests/open").json() if q["de_moi"])
    assert cli.post("/request/answer", json={"req_id": rid}).status_code == 409
    assert appels == []


def test_demande_inconnue_ou_echue(c):
    cli, appels = c
    assert cli.post("/request/answer", json={"req_id": "x-y"}).status_code == 404
    assert appels == []

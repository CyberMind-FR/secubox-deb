# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2542 — /assist/ : le panneau « En cours » montre demandes, offres et correspondances ; l'API dit d'où elles viennent, à qui elles sont, combien de temps il reste."""
import asyncio
import os
import sys
from pathlib import Path

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[3] / "common")
for p in (ANNUAIRE, CORE, str(Path(__file__).resolve().parents[1])):        # le dernier inséré passe devant : `api` doit être celui d'assist, pas celui de l'annuaire
    sys.path.insert(0, p)
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-test-journal.db")

from annuaire import assist_match  # noqa: E402
from api import main as A  # noqa: E402

MOI, AUTRE = "did:plc:moi00000000000000000000", "did:plc:autre0000000000000000000"
MAINTENANT = "2026-10-13T06:00:00Z"


def _id(did, suffixe):
    return assist_match.author_prefix(did) + "-" + suffixe


def _e(op, did, **payload):
    return {"op": op, "author": did, "payload": {"issued_by": did, **payload}}


ENTREES = [
    _e("assist_offer", AUTRE, offer_id=_id(AUTRE, "o1"), tags=["dns"], created_at="2026-10-13T05:38:02Z", ttl_s=3600),
    _e("assist_offer", MOI, offer_id=_id(MOI, "o2"), tags=["waf"], created_at="2026-10-13T05:59:00Z", ttl_s=3600),
    _e("assist_request_open", AUTRE, req_id=_id(AUTRE, "r1"), tags=["gk1"], reason="aide", created_at="2026-10-13T05:37:08Z", ttl_s=3600),
    {"op": "node_publish", "author": AUTRE, "payload": {"did": AUTRE, "boxname": "gk1"}},
    {"op": "node_publish", "author": MOI, "payload": {"did": MOI, "boxname": "gk2"}},
]


def _api(monkeypatch):
    monkeypatch.setattr(A, "_entries", lambda: ENTREES)
    monkeypatch.setattr(A, "_now", lambda: MAINTENANT)
    monkeypatch.setattr(A, "_self_did", lambda: MOI)


def test_offres_disent_noeud_proprietaire_et_temps_restant(monkeypatch):
    _api(monkeypatch)
    offres = {o["offer_id"].split("-")[1]: o for o in asyncio.run(A.offers())}
    assert offres["o1"]["noeud"] == "gk1" and offres["o1"]["de_moi"] is False and offres["o1"]["reste_s"] == 38 * 60 + 2
    assert offres["o2"]["noeud"] == "gk2" and offres["o2"]["de_moi"] is True and offres["o2"]["reste_s"] == 59 * 60


def test_demandes_ouvertes_disent_le_temps_restant(monkeypatch):
    _api(monkeypatch)
    r = asyncio.run(A.requests_open())[0]
    assert r["noeud"] == "gk1" and r["de_moi"] is False and r["reste_s"] == 3600 - (22 * 60 + 52)


def test_les_champs_d_origine_sont_conserves(monkeypatch):
    _api(monkeypatch)
    o = asyncio.run(A.offers())[0]
    assert o["tags"] and o["offer_id"] and o["issued_by"]


def test_temps_restant_jamais_negatif_ni_inventé():
    assert A._reste_s("2026-10-13T05:00:00Z", 60, "2026-10-13T06:00:00Z") == 0
    assert A._reste_s("", 60, "2026-10-13T06:00:00Z") is None
    assert A._reste_s("pas une date", 60, "2026-10-13T06:00:00Z") is None

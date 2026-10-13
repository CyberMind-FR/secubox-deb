# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2546 — /matches rend les paires COMPATIBLES qui nous concernent, avec l'état des deux côtés ; avant, seulement celles déjà acceptées des deux côtés.

Les boutons « Accepter » étaient posés sur cette liste : une paire n'y apparaissait qu'une fois acceptée — donc jamais acceptable."""
import asyncio
import os
import sys
from pathlib import Path

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[3] / "common")
for p in (ANNUAIRE, CORE, str(Path(__file__).resolve().parents[1])):
    sys.path.insert(0, p)
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-test-journal.db")

from annuaire import assist_match as AM  # noqa: E402
from api import main as A  # noqa: E402
from assist import rendezvous as R  # noqa: E402

GK1, GK2, GK3 = "did:plc:gk1000000000000000000000", "did:plc:gk2000000000000000000000", "did:plc:gk3000000000000000000000"
NOW = "2026-10-13T06:00:00Z"


def _id(did, s):
    return AM.author_prefix(did) + "-" + s


def _e(op, did, **p):
    return {"op": op, "author": did, "payload": {"issued_by": did, **p}}


def _accept(did, offer_id, req_id, side):
    return {"op": "assist_match_accept", "author": did,
            "payload": {"match_id": AM.match_id(offer_id, req_id), "offer_id": offer_id, "req_id": req_id, "side": side}}


OFFRE, DEMANDE = _id(GK2, "o1"), _id(GK1, "r1")
BASE = [
    _e("assist_offer", GK2, offer_id=OFFRE, tags=["gk1", "dns"], created_at="2026-10-13T05:38:00Z", ttl_s=3600),
    _e("assist_request_open", GK1, req_id=DEMANDE, tags=["gk1"], reason="aide", created_at="2026-10-13T05:37:00Z", ttl_s=3600),
    {"op": "node_publish", "author": GK1, "payload": {"did": GK1, "boxname": "gk1"}},
    {"op": "node_publish", "author": GK2, "payload": {"did": GK2, "boxname": "gk2"}},
]


def test_une_paire_compatible_non_acceptee_est_visible_des_deux_cotes():
    pour_gk1 = R.candidate_matches(BASE, GK1, NOW)
    pour_gk2 = R.candidate_matches(BASE, GK2, NOW)
    assert len(pour_gk1) == 1 and len(pour_gk2) == 1
    assert pour_gk1[0]["mon_cote"] == "request" and pour_gk2[0]["mon_cote"] == "offer"
    assert pour_gk1[0]["match_id"] == pour_gk2[0]["match_id"] == AM.match_id(OFFRE, DEMANDE)
    assert (pour_gk1[0]["offre_acceptee"], pour_gk1[0]["demande_acceptee"], pour_gk1[0]["prete"]) == (False, False, False)
    assert pour_gk1[0]["tags"] == ["gk1"]                                              # l'intersection, pas tous les tags de l'offre


def test_chaque_acceptation_n_est_creditee_qu_a_son_proprietaire():
    e = BASE + [_accept(GK2, OFFRE, DEMANDE, "offer")]
    c = R.candidate_matches(e, GK1, NOW)[0]
    assert (c["offre_acceptee"], c["demande_acceptee"], c["prete"]) == (True, False, False)
    e = e + [_accept(GK1, OFFRE, DEMANDE, "request")]
    c = R.candidate_matches(e, GK1, NOW)[0]
    assert (c["offre_acceptee"], c["demande_acceptee"], c["prete"]) == (True, True, True)


def test_une_acceptation_forgee_par_un_tiers_ne_compte_pas():
    e = BASE + [_accept(GK3, OFFRE, DEMANDE, "offer"), _accept(GK3, OFFRE, DEMANDE, "request")]
    c = R.candidate_matches(e, GK1, NOW)[0]
    assert (c["offre_acceptee"], c["demande_acceptee"], c["prete"]) == (False, False, False)


def test_une_acceptation_sur_un_autre_couple_ne_compte_pas():
    faux = _accept(GK2, OFFRE, DEMANDE, "offer")
    faux["payload"]["match_id"] = AM.match_id("autre", "couple")                       # match_id qui ne correspond pas aux ids annoncés
    assert R.candidate_matches(BASE + [faux], GK1, NOW)[0]["offre_acceptee"] is False


def test_les_paires_des_autres_ne_nous_concernent_pas():
    assert R.candidate_matches(BASE, GK3, NOW) == []


def test_on_ne_s_apparie_pas_avec_soi_meme():
    e = [_e("assist_offer", GK1, offer_id=_id(GK1, "o9"), tags=["gk1"], created_at="2026-10-13T05:38:00Z", ttl_s=3600)] + BASE[1:]
    assert all(c["offerer_did"] != c["requester_did"] for c in R.candidate_matches(e, GK1, NOW))


def test_des_tags_sans_rapport_ne_font_pas_de_paire():
    e = [_e("assist_offer", GK2, offer_id=_id(GK2, "o2"), tags=["waf"], created_at="2026-10-13T05:38:00Z", ttl_s=3600)] + BASE[1:]
    assert R.candidate_matches(e, GK1, NOW) == []


def test_une_demande_ou_une_offre_expiree_sort_de_la_liste():
    assert R.candidate_matches(BASE, GK1, "2026-10-13T08:00:00Z") == []


def test_ready_matches_reste_strict_pour_ouvrir_la_session():
    assert R.ready_matches(BASE, GK1, NOW) == []
    e = BASE + [_accept(GK2, OFFRE, DEMANDE, "offer"), _accept(GK1, OFFRE, DEMANDE, "request")]
    assert len(R.ready_matches(e, GK1, NOW)) == 1


def test_l_api_dit_les_noeuds_et_l_etat(monkeypatch):
    monkeypatch.setattr(A, "_entries", lambda: BASE + [_accept(GK2, OFFRE, DEMANDE, "offer")])
    monkeypatch.setattr(A, "_now", lambda: NOW)
    monkeypatch.setattr(A, "_self_did", lambda: GK1)
    m = asyncio.run(A.matches())[0]
    assert m["noeud_offre"] == "gk2" and m["noeud_demande"] == "gk1" and m["mon_cote"] == "request" and m["offre_acceptee"] is True and m["prete"] is False


def test_sans_identite_la_liste_est_vide(monkeypatch):
    monkeypatch.setattr(A, "_self_did", lambda: None)
    assert asyncio.run(A.matches()) == []

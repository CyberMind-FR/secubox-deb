# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2540 — demandes et offres d'assistance : voie rapide de synchronisation, et une synchro qui échoue se DIT.

Mesuré sur deux box : le journal entier (3 Mo, 5 136 entrées dont 5 061 bannissements) était tiré toutes les 300 s pour une cinquantaine d'entrées
d'assistance, et `except Exception: pass` ne laissait aucune trace d'un échec."""
import hashlib
import logging

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.mesh_sync import sync_once
from annuaire.model import Identity, MemberState, Op
from annuaire.verbs import export_entries


def _signe(journal, op, payload, cle=None):
    priv, pub = cle or generate_keypair()
    did = did_from_pubkey(pub)
    journal.append(op=op, payload_type="Test", payload=payload, author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return (priv, pub)


def _membre(journal):
    """L'auteur s'inscrit (INVITE_ACCEPT) : c'est de cette entrée que l'export tire sa clé publique."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32], state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    journal.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload, author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub


@pytest.fixture()
def journal(tmp_path):
    j = Journal(str(tmp_path / "a.db"))
    cle = _membre(j)
    for i in range(6):
        _signe(j, Op.BAN_PUBLISH, {"ip": f"198.51.100.{i}"}, cle)
    _signe(j, Op.ASSIST_OFFER, {"offer_id": "o1"}, cle)
    _signe(j, Op.ASSIST_REQUEST_OPEN, {"request_id": "r1"}, cle)
    return j


def test_export_filtre_par_prefixe_d_operation(journal):
    assert len(export_entries(journal)) == 9
    seul = export_entries(journal, ops=("assist_",))
    assert sorted(e["op"] for e in seul) == ["assist_offer", "assist_request_open"]


def test_export_sans_filtre_inchange(journal):
    assert {e["op"] for e in export_entries(journal)} >= {"ban_publish", "assist_offer"}


def test_sync_once_demande_seulement_les_operations_voulues(journal):
    vus = []

    def fetch(url):
        vus.append(url)
        return []
    sync_once(journal, [{"mesh_ip": "10.10.0.1"}], fetch=fetch, ops="assist_")
    sync_once(journal, [{"mesh_ip": "10.10.0.1"}], fetch=fetch)
    assert vus[0].endswith("/api/v1/annuaire/log/export?ops=assist_") and vus[1].endswith("/api/v1/annuaire/log/export")


def test_la_voie_rapide_ne_transporte_que_l_assistance_et_converge(journal, tmp_path):
    autre = Journal(str(tmp_path / "b.db"))
    res = sync_once(autre, [{"mesh_ip": "10.10.0.1"}], fetch=lambda url: export_entries(journal, ops=("assist_",)), ops="assist_")
    assert res["ingested"] == 2 and res["rejected"] == 0
    assert sorted(e["op"] for e in export_entries(autre)) == ["assist_offer", "assist_request_open"]


def test_un_cycle_qui_echoue_est_journalise_et_ne_leve_pas(monkeypatch, caplog):
    import api.main as m

    def boom(*a, **k):
        raise RuntimeError("pair injoignable")
    monkeypatch.setattr("annuaire.mesh_sync.sync_once", boom)
    monkeypatch.setattr("annuaire.mesh_sync.read_mesh_peers", lambda p: [{"mesh_ip": "10.10.0.1"}])
    with caplog.at_level(logging.WARNING, logger="secubox.annuaire.sync"):
        assert m._cycle_sync("/x", ops="assist_") is None
    assert "pair injoignable" in caplog.text and "assist_" in caplog.text


def test_un_cycle_qui_ingere_le_dit(monkeypatch, caplog):
    import api.main as m
    monkeypatch.setattr("annuaire.mesh_sync.sync_once", lambda *a, **k: {"peers": 1, "ingested": 2, "skipped": 0, "rejected": 0, "errors": 0})
    monkeypatch.setattr("annuaire.mesh_sync.read_mesh_peers", lambda p: [{"mesh_ip": "10.10.0.1"}])
    with caplog.at_level(logging.INFO, logger="secubox.annuaire.sync"):
        res = m._cycle_sync("/x", ops="assist_")
    assert res["ingested"] == 2 and "ingéré" in caplog.text


def test_un_cycle_qui_ne_change_rien_reste_silencieux(monkeypatch, caplog):
    import api.main as m
    monkeypatch.setattr("annuaire.mesh_sync.sync_once", lambda *a, **k: {"peers": 1, "ingested": 0, "skipped": 50, "rejected": 0, "errors": 0})
    monkeypatch.setattr("annuaire.mesh_sync.read_mesh_peers", lambda p: [{"mesh_ip": "10.10.0.1"}])
    with caplog.at_level(logging.INFO, logger="secubox.annuaire.sync"):
        m._cycle_sync("/x", ops="assist_")
    assert caplog.text == ""


def test_la_voie_rapide_a_son_intervalle_et_une_route_manuelle():
    import api.main as m
    src = open(m.__file__, encoding="utf-8").read()
    assert "ANNUAIRE_ASSIST_SYNC_INTERVAL" in src and '"20"' in src
    assert '@app.post("/sync/now"' in src

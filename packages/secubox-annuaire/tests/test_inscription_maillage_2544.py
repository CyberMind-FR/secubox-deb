# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2544 — une box qui rejoint le maillage APRÈS le démarrage de l'annuaire s'inscrit chez le maître au passage de synchro suivant.

Avant, `_publish_self_node` ne tournait qu'au démarrage : sans maillage à ce moment-là (box neuve), il ne réessayait jamais — le maître ne voyait
la box ni dans la flotte ni dans l'assistance."""
import hashlib
import secrets

import pytest

import api.main as m
from annuaire.crypto import canonical_bytes, did_from_pubkey, public_from_private, sign
from annuaire.log import Journal
from annuaire.model import Identity, MemberState, Op

META = {"node_id": "sbx-aaaa", "boxname": "gk1", "pubkey_wg": "WGPUB", "mesh_ip": "10.10.0.3", "ddns": "gk1.secubox.in", "endpoint": None}


@pytest.fixture()
def box(tmp_path, monkeypatch):
    cle = tmp_path / "node.key"
    priv_hex = secrets.token_hex(32)
    cle.write_text(priv_hex)
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(cle))
    j = Journal(str(tmp_path / "j.db"))
    # `annuairectl init` : la box est membre de son propre annuaire ; sans cette entrée, la signature d'un NodeRecord n'a pas de clé connue.
    priv = bytes.fromhex(priv_hex)
    pub = public_from_private(priv)
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32], state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    j.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload, author=did, sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    monkeypatch.setattr(m, "get_journal", lambda: j)
    monkeypatch.setattr(m, "_NOEUD_INSCRIT", False, raising=False)
    return j, cle


def _publications(j):
    return [e for e in j.iter_entries() if (e.op.value if hasattr(e.op, "value") else e.op) == Op.NODE_PUBLISH.value]


def test_sans_cle_d_identite_rien_n_est_inscrit(box, monkeypatch):
    j, cle = box
    cle.unlink()
    monkeypatch.setattr("annuaire.mesh_sync.read_self_meta", lambda *a, **k: META)
    assert m._publish_self_node() is False and _publications(j) == []


def test_sans_maillage_on_reessaiera(box, monkeypatch):
    j, _ = box
    monkeypatch.setattr("annuaire.mesh_sync.read_self_meta", lambda *a, **k: None)
    assert m._publish_self_node() is False and _publications(j) == []


def test_avec_maillage_la_box_s_inscrit_une_seule_fois(box, monkeypatch):
    j, _ = box
    monkeypatch.setattr("annuaire.mesh_sync.read_self_meta", lambda *a, **k: META)
    assert m._publish_self_node() is True and len(_publications(j)) == 1
    assert m._publish_self_node() is True and len(_publications(j)) == 1          # idempotent : aucun doublon dans le journal


def test_la_boucle_reessaie_jusqu_a_l_inscription_puis_se_tait(box, monkeypatch):
    j, _ = box
    appels = []
    etats = iter([None, None, META])                                       # le maillage n'arrive qu'au 3e passage
    monkeypatch.setattr("annuaire.mesh_sync.read_self_meta", lambda *a, **k: (appels.append(1), next(etats, META))[1])
    for _ in range(5):
        m._inscrire_si_besoin()
    assert len(_publications(j)) == 1 and len(appels) == 3                  # ni inscription tant que le maillage manque, ni relecture une fois inscrit


def test_la_voie_rapide_et_le_cycle_complet_appellent_l_inscription():
    src = open(m.__file__, encoding="utf-8").read()
    assert src.count("_inscrire_si_besoin") >= 3          # définition + cycle complet + voie rapide

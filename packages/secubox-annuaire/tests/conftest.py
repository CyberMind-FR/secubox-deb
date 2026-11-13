# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/conftest.py
Pytest configuration — path bootstrap so `from annuaire import ...` works ; fixtures partagées du maillage (`j`, `api`) et
`_membre` (#3666, F17 : plus d'import entre modules de test).
"""
import hashlib
import os
import sys

import pytest

# Insert the package root (secubox-annuaire/) into the path so that
# `from annuaire import ...` resolves without an installed egg.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)


def _membre(j):
    """Nouveau membre (Identity MEMBER) inscrit au journal `j` : (clé privée, clé publique, did)."""
    from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
    from annuaire.model import Identity, MemberState, Op
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
                     state=MemberState.MEMBER)
    payload = {k: v for k, v in ident.model_dump().items() if k not in ("sig", "signer_did")}
    j.append(op=Op.INVITE_ACCEPT, payload_type="Identity", payload=payload, author=did,
             sig=sign(priv, canonical_bytes(payload)), author_pubkey_hex=pub.hex())
    return priv, pub, did


@pytest.fixture
def j(tmp_path):
    from annuaire.log import Journal
    return Journal(str(tmp_path / "j.db"))


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DIR_SYNC", "0")
    from fastapi.testclient import TestClient
    from api import main as M
    M._journal = None
    M._DB_PATH = str(tmp_path / "journal.db")
    M._EXPORT_CACHE.update(hauteur=None, donnees=None)
    jj = M.get_journal()
    priv, _pub, did = _membre(jj)
    cle = tmp_path / "node.key"
    cle.write_text(priv.hex())
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(cle))
    monkeypatch.setattr(M, "MIRRORNET_EXPORT", tmp_path / "mirrornet-export.json")
    monkeypatch.setattr(M, "AUDIT_DROITS", tmp_path / "audit.log")
    monkeypatch.setattr(M, "JOIGNABILITE_ETAT", tmp_path / "joignabilite.json")
    tc = TestClient(M.app)
    yield tc, M, jj, did, tmp_path
    M.app.dependency_overrides.clear()

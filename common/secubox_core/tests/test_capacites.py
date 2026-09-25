# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1438 — le middleware de capacités : session → appareil → personne → capacités."""
import asyncio
import json
import sqlite3
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from secubox_core import capacites as C, sbxid as S, user_store


def _cle():
    k = ec.generate_private_key(ec.SECP256R1())
    return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


@pytest.fixture
def banc(tmp_path, monkeypatch):
    pm, pg, pr = _cle(), _cle(), _cle()
    dem = {"demandes": [
        {"cle_publique": pm, "etat": "acceptee", "profil": "user", "jtis": ["j-membre"]},
        {"cle_publique": pg, "etat": "acceptee", "profil": "guest", "jtis": ["j-invite"]},
        {"cle_publique": pr, "etat": "acceptee", "profil": "user", "jtis": ["j-revoque"]},
    ]}
    (tmp_path / "d.json").write_text(json.dumps(dem))
    db = sqlite3.connect(tmp_path / "sbx.db")
    S.initialise(db)
    for pseudo, cle, role, rev in (("alice", pm, "member", None), ("bob", pg, "guest", None), ("eve", pr, "member", 1)):
        u = str(uuid.uuid4())
        db.execute("INSERT INTO sbx_users (user_uuid,pseudo,home_node,created_at) VALUES (?,?,?,?)", (u, pseudo, "n", 0))
        db.execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (u, role, "t", 0))
        db.execute("INSERT INTO sbx_devices (device_uuid,user_uuid,device_name,did,public_key,created_at,revoked_at)"
                   " VALUES (?,?,?,?,?,?,?)", (str(uuid.uuid4()), u, "x", S.did_appareil(cle), cle, 0, rev))
    db.commit()
    monkeypatch.setattr(C, "DEMANDES", tmp_path / "d.json")
    monkeypatch.setattr(C, "SBX_DB", tmp_path / "sbx.db")
    monkeypatch.setattr(user_store, "get_user", lambda s: {"gk2": {"role": "admin", "enabled": True}}.get(s))
    C._CACHE.clear()


@pytest.mark.parametrize("payload,peut", [
    ({"sub": "gk2", "jti": "x"}, True),               # l'exploitant système
    ({"sub": "gk2", "jti": "j-membre"}, True),
    ({"sub": "sbx-z", "jti": "j-membre"}, True),       # membre : billets.publish
    ({"sub": "sbx-z", "jti": "j-invite"}, False),      # invité : lecture seule
    ({"sub": "sbx-z", "jti": "j-revoque"}, False),     # appareil révoqué
    ({"sub": "inconnu", "jti": "?"}, False),
])
def test_capacite_billets(banc, payload, peut):
    assert ("billets.publish" in C.capacites_du_porteur(payload)) is peut


def test_repli_sans_sbxdb(banc, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "SBX_DB", tmp_path / "absent.db")
    C._CACHE.clear()
    assert "billets.publish" in C.capacites_du_porteur({"sub": "sbx-z", "jti": "j-membre"})
    assert "billets.publish" not in C.capacites_du_porteur({"sub": "sbx-z", "jti": "j-invite"})


def test_dependance_refuse_et_accepte(banc):
    garde = C.require_capability("metablog.publish")
    with pytest.raises(HTTPException) as e:
        asyncio.run(garde({"sub": "sbx-z", "jti": "j-membre"}))   # membre : pas metablog.publish
    assert e.value.status_code == 403
    assert asyncio.run(garde({"sub": "gk2", "jti": "x"}))["sub"] == "gk2"
    with pytest.raises(S.Refus):
        C.require_capability("ssh.login")

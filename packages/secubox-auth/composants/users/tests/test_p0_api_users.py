# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1409 — l'API users ne rend plus de secret et ne se laisse plus muter par
n'importe quel porteur de JWT ; les révocations de session marchent."""
import asyncio
import json
import os
from pathlib import Path

import pytest

import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[5] / "secubox.conf.example"]

main = pytest.importorskip("api.main")
from secubox_core.auth import require_jwt  # noqa: E402

# Routes volontairement lisibles sans permission particulière.
PUBLIQUES = {"/health", "/status", "/services", "/components", "/access",
             "/permissions", "/roles", "/role/{role_id}", "/acl"}


def _deps(route):
    return [d.call for d in route.dependant.dependencies]


def test_aucune_route_n_est_gardee_par_le_seul_jwt():
    """S2 : `require_jwt` seul laissait un appareil guest se promouvoir."""
    fautives = []
    for r in main.app.routes:
        if not hasattr(r, "dependant") or r.path in PUBLIQUES:
            continue
        if require_jwt in _deps(r):
            fautives.append(f"{sorted(r.methods)} {r.path}")
    assert fautives == []


def _users(tmp_path, monkeypatch, users):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": users, "groups": []}))
    monkeypatch.setattr(main, "load_users", lambda: json.loads(p.read_text()))


SECRET = {"username": "gk2", "role": "admin", "password_hash": "$argon2id$SECRET",
          "totp": {"enabled": True, "secret": "JBSWY3DPEHPK3PXP",
                   "backup_codes": [{"hash": "$argon2id$CODE"}]}, "services": []}


def test_liste_et_fiche_expurgees(tmp_path, monkeypatch):
    """S1 : ni haché, ni secret TOTP, ni code de secours."""
    _users(tmp_path, monkeypatch, [dict(SECRET)])
    monkeypatch.setattr(main, "check_service", lambda s: "ok")
    brut = json.dumps(asyncio.run(main.list_users())) + json.dumps(asyncio.run(main.get_user("gk2")))
    for fuite in ("SECRET", "JBSWY3DPEHPK3PXP", "$argon2id$CODE", "password_hash"):
        assert fuite not in brut, fuite
    assert '"totp_enabled": true' in brut


def test_revocations_ecrivent_une_liste(tmp_path, monkeypatch):
    f = tmp_path / "sessions.json"
    f.write_text(json.dumps([{"id": "a1", "username": "gk2"}, {"id": "b2", "username": "op"}]))
    monkeypatch.setattr(main, "SESSIONS_FILE", str(f))
    assert main.revoke_session("a1")["success"]
    assert json.loads(f.read_text()) == [{"id": "b2", "username": "op"}]
    assert main.revoke_all_sessions()["revoked"] == 1
    assert json.loads(f.read_text()) == []          # une LISTE, pas un dict


def test_revocation_repare_l_ancien_format(tmp_path, monkeypatch):
    f = tmp_path / "sessions.json"
    f.write_text(json.dumps({"sessions": [{"id": "c3"}], "revoked_at": "x"}))
    monkeypatch.setattr(main, "SESSIONS_FILE", str(f))
    main.revoke_session("c3")
    assert json.loads(f.read_text()) == []


FUITES = ("SECRET", "JBSWY3DPEHPK3PXP", "$argon2id$CODE", "password_hash")


def _sans_fuite(obj):
    brut = json.dumps(obj)
    for fuite in FUITES:
        assert fuite not in brut, fuite
    return brut


def test_export_expurge(tmp_path, monkeypatch):
    """#1753 : l'export portait empreintes et secrets TOTP (e1d29ab37 effacé)."""
    _users(tmp_path, monkeypatch, [dict(SECRET)])
    brut = _sans_fuite(asyncio.run(main.export_users()))
    assert '"totp_enabled": true' in brut and '"gk2"' in brut


class _MoteurFactice:
    def __init__(self):
        self.rec = json.loads(json.dumps(SECRET))
    def get_user(self, name):
        return json.loads(json.dumps(self.rec)) if name == self.rec["username"] else None
    def create_user(self, name, email=None, role=None):
        self.rec = dict(json.loads(json.dumps(SECRET)), username=name, email=email, role=role)
        return json.loads(json.dumps(self.rec))
    def _load(self):
        return {"version": 2, "users": [self.rec], "groups": []}
    def _save(self, doc):
        pass


def test_modification_rend_une_fiche_expurgee(monkeypatch):
    """#1753 : `PUT /user/{u}` rendait l'enregistrement brut à tout porteur
    de `users.edit` — empreinte et secret TOTP de l'admin compris."""
    monkeypatch.setattr(main, "_engine", _MoteurFactice())
    _sans_fuite(asyncio.run(main.update_user("gk2", main.UserUpdate())))


def test_creation_rend_une_fiche_expurgee(monkeypatch):
    monkeypatch.setattr(main, "_engine", _MoteurFactice())
    r = main.create_user(main.UserCreate(username="nouveau", email="n@exemple.invalid",
                                         password="x", services=[], forcer=False))
    _sans_fuite(r)
    assert r["user"]["username"] == "nouveau"

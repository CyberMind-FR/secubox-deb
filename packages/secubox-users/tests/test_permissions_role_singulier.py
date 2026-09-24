# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1377 — un compte `role: "admin"` (singulier, v2) a les droits d'admin."""
import json
import os
from pathlib import Path

import pytest

# Un /etc/secubox/secubox.conf présent mais illisible (poste de dev) fait
# échouer l'import : on ne garde que les chemins lisibles.
import secubox_core.config as _conf
_conf._CONF_PATHS[:] = [p for p in _conf._CONF_PATHS if os.access(p, os.R_OK)] or \
    [Path(__file__).resolve().parents[3] / "secubox.conf.example"]

main = pytest.importorskip("api.main")


def _users(tmp_path, monkeypatch, users):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": users, "groups": []}))
    monkeypatch.setattr(main, "load_users", lambda: json.loads(p.read_text()))
    monkeypatch.setattr(main, "load_roles", lambda: [dict(r) for r in main.DEFAULT_ROLES])


def test_un_admin_au_singulier_a_users_view(tmp_path, monkeypatch):
    _users(tmp_path, monkeypatch, [{"username": "gk2", "role": "admin"}])
    assert main.user_has_permission("gk2", "users.view")
    assert main.user_has_permission("gk2", "users.edit")


def test_un_operateur_n_est_pas_admin(tmp_path, monkeypatch):
    _users(tmp_path, monkeypatch, [{"username": "operator", "role": "operator"}])
    perms = set(main.get_user_permissions("operator"))
    op = next(r for r in main.DEFAULT_ROLES if r["id"] == "operator")
    assert perms == set(op["permissions"])


def test_la_liste_roles_reste_lue(tmp_path, monkeypatch):
    _users(tmp_path, monkeypatch, [{"username": "x", "roles": ["admin"]}])
    assert main.user_has_permission("x", "users.edit")


def test_un_inconnu_n_a_rien(tmp_path, monkeypatch):
    _users(tmp_path, monkeypatch, [])
    assert main.get_user_permissions("personne") == []

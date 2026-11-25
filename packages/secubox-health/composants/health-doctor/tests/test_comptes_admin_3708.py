# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3708 : la santé avertit d'un administrateur actif sans mot de passe, sans jamais publier de nom."""
import importlib
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[5]
API = ROOT / "packages/secubox-health/composants/health-doctor/api"


@pytest.fixture
def api(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(ROOT / "common"))
    monkeypatch.setenv("SECUBOX_CONF", str(tmp_path / "absent.conf"))
    monkeypatch.setenv("SECUBOX_AUTH_DELEGUES", str(tmp_path / "absent.json"))
    pkg = types.ModuleType("hd3708")
    pkg.__path__ = [str(API)]
    monkeypatch.setitem(sys.modules, "hd3708", pkg)
    checks, runner = importlib.import_module("hd3708.checks"), importlib.import_module("hd3708.runner")
    monkeypatch.setattr(runner, "CACHE_PATH", tmp_path / "cache.json")
    yield checks, runner
    for n in ("hd3708.checks", "hd3708.runner"):
        sys.modules.pop(n, None)


def _users(tmp_path, *comptes):
    f = tmp_path / "users.json"
    f.write_text(json.dumps({"version": 2, "users": [
        {"username": n, "role": r, "enabled": e, "password_hash": h} for n, r, e, h in comptes]}))
    return f


def test_un_orphelin_est_signale_sans_son_nom(api, tmp_path):
    f = _users(tmp_path, ("chef", "admin", True, "$argon2id$x"), ("orphelin-secret", "admin", True, None))
    ok, d = api[0].check_comptes_admin(f)
    assert ok is False and d["sans_mot_de_passe"] == 1 and "orphelin" not in json.dumps(d)


def test_rien_a_signaler(api, tmp_path):
    f = _users(tmp_path, ("chef", "admin", True, "$argon2id$x"), ("coupe", "admin", False, None),
               ("usager", "viewer", True, None), ("console", "admin", True, None))
    assert api[0].check_comptes_admin(f) == (True, {"sans_mot_de_passe": 0})


def test_registre_illisible_n_invente_rien(api, tmp_path):
    ok, d = api[0].check_comptes_admin(tmp_path / "absent")
    assert ok is True and d["skipped"] is True


def test_avertissement_hors_des_services_vitaux(api, tmp_path, monkeypatch):
    checks, runner = api
    f = _users(tmp_path, ("orphelin-secret", "admin", True, None))
    monkeypatch.setattr(checks, "REGISTRY", {"temoin": lambda: (True, {})})
    monkeypatch.setattr(checks, "REGISTRY_AVERTISSEMENTS", {"comptes-admin": lambda: checks.check_comptes_admin(f)})
    etat = runner.run_once()
    s = etat["summary"]
    assert (s["total"], s["ok"], s["fail"], s["avertissements"]) == (1, 1, 0, 1)
    assert etat["checks"]["comptes-admin"]["niveau"] == "avertissement"
    assert "orphelin" not in (tmp_path / "cache.json").read_text()


def test_la_page_sante_montre_l_avertissement():
    t = (ROOT / "packages/secubox-hub/www/health/index.html").read_text()
    assert "rendAvertissements(s && s.checks)" in t and 'id="avSection"' in t

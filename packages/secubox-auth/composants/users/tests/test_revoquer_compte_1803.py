# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""« Révoquer les sessions » d'un compte coupe vraiment ses sessions (#1803).

Le moteur du module users n'avait pas de rappel de révocation (seul
secubox-auth en câblait un) : le bouton rendait 0 et ne coupait rien.
"""
import json


def test_le_rappel_est_cable_et_coupe_les_sessions_du_compte(tmp_path, monkeypatch):
    reg = tmp_path / "sessions.json"
    reg.write_text(json.dumps([{"id": "a", "username": "gk2"}, {"id": "b", "username": "operator"},
                               {"id": "c", "username": "gk2"}]))
    from api import main as M
    monkeypatch.setattr(M, "SESSIONS_FILE", str(reg))
    assert M._engine._revoke_cb is not None, "le moteur doit avoir un rappel de révocation"
    assert M._engine.revoke_sessions("gk2") == 2
    assert [r["id"] for r in json.loads(reg.read_text())] == ["b"]


def test_revoquer_tout_ecrit_une_liste_vide(tmp_path, monkeypatch):
    reg = tmp_path / "sessions.json"
    reg.write_text(json.dumps([{"id": "a", "username": "gk2"}]))
    from api import main as M
    monkeypatch.setattr(M, "SESSIONS_FILE", str(reg))
    M._ecrire_sessions(lambda rows: [])
    assert json.loads(reg.read_text()) == []

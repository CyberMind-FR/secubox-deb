# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Premier Pas (#3442) : le frontal HAProxy relancé une fois le domaine posé. Exécuteur factice."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from premier_pas import moteur as M  # noqa: E402
from test_premier_pas import CONNUS, complet, isole  # noqa: E402,F401


# ── #3442 : le frontal HAProxy relancé une fois le domaine posé ──────────────────────────────────
def _outil(tmp_path):
    outil = tmp_path / "haproxyctl"
    outil.write_text("#!/bin/sh\n")
    outil.chmod(0o755)
    return outil


def test_frontal_apres_domaine_et_services(complet, tmp_path, monkeypatch):
    monkeypatch.setattr(M, "HAPROXYCTL", _outil(tmp_path))
    actions = M.plan(complet)
    argvs = [a.argv for a in actions]
    i = argvs.index([str(M.HAPROXYCTL), "frontal"])
    quois = [a.quoi for a in actions]
    assert any(q.startswith("domaine ") for q in quois[:i])
    assert any(a.argv and a.argv[0] == "secubox-profilectl" for a in actions[:i])
    assert actions[i].souple


def test_frontal_absent_en_lan_sans_domaine(complet, tmp_path, monkeypatch):
    complet["reseau"] = {"mode": "lan"}
    monkeypatch.setattr(M, "HAPROXYCTL", _outil(tmp_path))
    assert not any(a.argv and a.argv[-1] == "frontal" for a in M.plan(complet))


def test_frontal_absent_sans_haproxyctl(complet, monkeypatch):
    monkeypatch.setattr(M, "HAPROXYCTL", Path("/nonexistent/haproxyctl"))
    assert not any(a.argv and a.argv[-1] == "frontal" for a in M.plan(complet))


def test_frontal_refuse_ne_bloque_pas(complet, isole, tmp_path, monkeypatch):
    monkeypatch.setattr(M, "HAPROXYCTL", _outil(tmp_path))
    monkeypatch.setattr(M, "NET_DETECT", _outil(tmp_path))
    def exe(argv):
        return (1, "ERROR: frontal : nginx -t refuse") if argv[-1] == "frontal" else (0, "")
    r = M.appliquer(complet, exe, CONNUS, isole / "fait")
    assert r.ok and any("frontal" in w for w in r.avertissements)

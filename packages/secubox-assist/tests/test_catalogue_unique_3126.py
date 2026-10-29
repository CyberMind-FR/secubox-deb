# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Un seul catalogue d'actions (#3126 L2, tâche 9, R-L2-4) : le support passe par le pilotage."""
import ast
import os
import sys
from pathlib import Path

import pytest

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[2].parent / "common")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-3126-test-journal.db")

from fastapi.testclient import TestClient  # noqa: E402
from secubox_core.auth import require_jwt  # noqa: E402

from api.main import app  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REMPLACE_PAR = "/api/v1/pilotage/boxes/<nom>/support"

ROUTES_SESSION = [
    ("GET", "/sessions", None),
    ("POST", "/request", {"center_did": "did:plc:x", "mode": "m", "scope": "s", "duration_s": 60, "reason": "r"}),
    ("POST", "/open", {"req_id": "r", "center_did": "did:plc:x", "duration_s": 60}),
    ("POST", "/close", {"session_id": "s"}),
    ("POST", "/console/grant", {"session_id": "s", "duration_s": 900}),
    ("POST", "/console/revoke", {"session_id": "s"}),
]


@pytest.fixture()
def admin():
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin", "role": "admin"}
    yield TestClient(app)
    app.dependency_overrides.pop(require_jwt, None)


@pytest.mark.parametrize("methode,chemin,corps", ROUTES_SESSION)
def test_routes_de_session_rendent_410(admin, methode, chemin, corps):
    r = admin.request(methode, chemin, json=corps)
    assert r.status_code == 410
    body = r.json()
    assert body["remplace_par"] == REMPLACE_PAR
    assert "pilotage" in body["detail"]


@pytest.mark.parametrize("methode,chemin,corps", ROUTES_SESSION)
def test_sans_authentification_401_pas_410(methode, chemin, corps):
    r = TestClient(app).request(methode, chemin, json=corps)
    assert r.status_code in (401, 403)
    assert "remplace_par" not in r.text


def test_le_marche_reste_servi(admin):
    assert admin.get("/offers").status_code != 410


def _imports(chemin: Path) -> set:
    arbre = ast.parse(chemin.read_text())
    out = set()
    for n in ast.walk(arbre):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            base = ("." * n.level) + (n.module or "")
            out.add(base)
            out |= {f"{base}.{a.name}".lstrip(".") for a in n.names}
    return out


def test_le_demon_n_importe_plus_le_catalogue():
    for nom in ("daemon.py", "wsserver.py", "diag.py", "console.py", "escalate.py"):
        p = ROOT / "assist" / nom
        if p.exists():
            assert not any("catalog" in i for i in _imports(p)), nom
    assert not (ROOT / "assist" / "catalog.py").exists()


def test_le_ctl_n_execute_plus_d_actions_de_catalogue():
    ctl = (ROOT / "sbin" / "secubox-assistctl").read_text()
    assert "assist.catalog" not in ctl
    assert "cmd_service" not in ctl and "cmd_config" not in ctl


@pytest.mark.asyncio
async def test_le_demon_refuse_toute_action_et_renvoie_au_pilotage(monkeypatch, tmp_path):
    from assist import audit, wsserver
    monkeypatch.setattr(audit, "AUDIT_PATH", str(tmp_path / "audit.log"))
    out = await wsserver.dispatch({"session_id": "s", "center_did": "c"}, "service.restart",
                                  "secubox-dns", [], "did:plc:x", "2026-10-29T00:00:00Z")
    assert out["ok"] is False
    assert out["remplace_par"] == REMPLACE_PAR


def test_plus_de_sudoers_ni_de_nnp_false_pour_le_demon():
    assert not (ROOT / "sudoers").exists()
    svc = (ROOT / "systemd" / "secubox-assist.service").read_text()
    assert "NoNewPrivileges=true" in svc
    assert "sudoers" not in (ROOT / "debian" / "secubox-assist.install").read_text()
    assert "rm_conffile /etc/sudoers.d/secubox-assist" in (ROOT / "debian" / "maintscript").read_text()


def test_la_page_annonce_le_pilotage_avec_un_lien():
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    assert 'id="avis-pilotage"' in html
    assert 'href="/fleet/"' in html
    assert "status === 410" in html

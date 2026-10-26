# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3190 — un `wgctl dump` en échec n'est pas « aucun pair » : 503, jamais total 0."""
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT.parents[1] / "common"
for p in (str(CORE), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

try:
    from api import main as wg  # noqa: E402
except Exception as e:  # pragma: no cover
    pytest.skip(f"api.main non importable : {e}", allow_module_level=True)

DUMP_OK = (
    "wg0\tPRIVATE\tPUBIFACE=\t51820\toff\n"
    "wg0\tPUBPEER=\t(none)\t203.0.113.7:51820\t10.0.0.2/32\t0\t10\t20\toff\n"
)


@pytest.fixture
def client():
    wg.app.dependency_overrides[wg.require_jwt] = lambda: {"sub": "admin"}
    yield TestClient(wg.app)
    wg.app.dependency_overrides.clear()


def _dump(monkeypatch, *, rc=0, out="", exc=None, err=""):
    def faux(*a, **k):
        if exc:
            raise exc
        return SimpleNamespace(returncode=rc, stdout=out, stderr=err)
    monkeypatch.setattr(wg.subprocess, "run", faux)


ROUTES = ["/peers/status", "/summary"]
PANNES = [
    dict(rc=1, err="Permission denied"),
    dict(exc=subprocess.TimeoutExpired("wgctl", 5)),
    dict(exc=OSError("sudo introuvable")),
]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("panne", PANNES)
def test_panne_rend_503(client, monkeypatch, route, panne):
    _dump(monkeypatch, **panne)
    r = client.get(route)
    assert r.status_code == 503
    assert r.json()["detail"].startswith("wgctl dump en échec : ")


@pytest.mark.parametrize("route", ROUTES)
def test_succes_forme_inchangee(client, monkeypatch, route):
    _dump(monkeypatch, out=DUMP_OK)
    r = client.get(route)
    assert r.status_code == 200
    j = r.json()
    assert "PRIVATE" not in r.text
    if route == "/summary":
        assert j["totals"]["total_peers"] == 1
    else:
        assert j["peers"][0]["full_key"] == "PUBPEER="


def test_collecteur_ne_plante_pas_sur_panne(monkeypatch):
    _dump(monkeypatch, rc=1)
    with pytest.raises(wg.WgDumpError):
        wg._parse_wg_show()

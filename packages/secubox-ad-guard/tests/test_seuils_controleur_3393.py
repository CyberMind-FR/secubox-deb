# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3393 : `POST /learn/thresholds` ne peut pas écrire filters.json (secubox-toolbox 664, dossier root 755) depuis l'agrégateur (secubox).
L'écriture passe par le verbe root borné `secubox-adguard-tv seuils` (données sur l'entrée standard, revalidées, verrou, audit) ;
l'API rend 503 « écriture non autorisée » si sudo ou le verbe manquent, jamais 500."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secubox_core.auth import require_jwt
from api import main as m

ICI = Path(__file__).resolve().parents[1]
CTL = ICI / "sbin" / "secubox-adguard-tv"


@pytest.fixture
def box(tmp_path, monkeypatch):
    f = tmp_path / "filters.json"
    f.write_text(json.dumps({"autolearn": True, "autolearn_min_sites": 2, "tor": {"actif": True}}))
    racine = tmp_path / "root"
    racine.mkdir(mode=0o700)
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_SANS_ROOT", "1")
    monkeypatch.setenv("PYTHONPATH", str(ICI.parents[1] / "common"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_FILTERS", str(f))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_APPLIQUE", str(racine / "applique.json"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(m, "_argv_seuils", lambda: [sys.executable, str(CTL), "seuils"])
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path
    m.app.dependency_overrides.pop(require_jwt, None)


def test_api_trace_inattendue_jamais_relayee(box, monkeypatch):
    faux = box / "faux-ctl"
    faux.write_text("#!/bin/sh\necho 'Traceback (most recent call last):' >&2\nexit 1\n")
    faux.chmod(0o755)
    monkeypatch.setattr(m, "_argv_seuils", lambda: [str(faux)])
    r = TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 4})
    assert r.status_code == 503 and "Traceback" not in r.text


def _ctl(entree: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(CTL), "seuils"], input=entree, capture_output=True, text=True, timeout=30)


def test_api_ecrit_par_le_controleur_et_audite(box):
    f = box / "filters.json"
    st0 = f.stat()
    r = TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 5})
    assert r.status_code == 200, r.text
    assert r.json()["changed"] == {"autolearn_min_sites": 5}
    assert json.loads(f.read_text()) == {"autolearn": True, "autolearn_min_sites": 5, "tor": {"actif": True}}
    assert f.stat().st_ino == st0.st_ino and f.stat().st_mode == st0.st_mode            # en place
    ligne = json.loads((box / "audit.log").read_text().splitlines()[-1])
    assert ligne["action"] == "seuils" and "autolearn_min_sites=5" in ligne["detail"]


def test_dossier_non_inscriptible_ecrit_en_place(box):
    os.chmod(box, 0o555)
    try:
        assert TestClient(m.app).post("/learn/thresholds", json={"autolearn_ti_min_weight": 0}).status_code == 200
    finally:
        os.chmod(box, 0o755)
    assert json.loads((box / "filters.json").read_text())["autolearn_ti_min_weight"] == 0


@pytest.mark.parametrize("entree", ["", "pas du json", "[]", '{"seuils": {}}', '{"acteur": "admin", "seuils": {}}',
                                    '{"acteur": "admin", "seuils": {"inconnu": 1}}',
                                    '{"acteur": "admin", "seuils": {"autolearn_min_sites": 0}}',
                                    '{"acteur": "admin", "seuils": {"autolearn_min_sites": true}}',
                                    '{"acteur": "admin", "seuils": {"autolearn_min_sites": 2.0}}',
                                    '{"acteur": "a b", "seuils": {"autolearn_min_sites": 2}}',
                                    '{"acteur": "admin", "seuils": {"autolearn_min_sites": 2}, "en_plus": 1}'])
def test_controleur_revalide_l_entree(box, entree):
    avant = (box / "filters.json").read_text()
    r = _ctl(entree)
    assert r.returncode == 2, r.stderr
    assert (box / "filters.json").read_text() == avant


def test_controleur_refuse_lien_et_absent(box):
    f = box / "filters.json"
    cible = box / "ailleurs.json"
    cible.write_text("{}")
    f.unlink()
    ok = '{"acteur": "admin", "seuils": {"autolearn_min_sites": 3}}'
    assert _ctl(ok).returncode == 4 and not f.exists()
    os.symlink(cible, f)
    assert _ctl(ok).returncode == 4 and cible.read_text() == "{}"


def test_api_409_si_filters_absent(box):
    (box / "filters.json").unlink()
    assert TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 4}).status_code == 409


def test_api_503_si_controleur_absent(box, monkeypatch):
    monkeypatch.setattr(m, "_argv_seuils", lambda: [str(box / "nexiste-pas"), "seuils"])
    r = TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 4})
    assert r.status_code == 503 and "écriture non autorisée" in r.json()["detail"]


def test_api_503_si_sudo_refuse(box, monkeypatch):
    faux = box / "faux-sudo"
    faux.write_text("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n")
    faux.chmod(0o755)
    monkeypatch.setattr(m, "_argv_seuils", lambda: [str(faux)])
    r = TestClient(m.app).post("/learn/thresholds", json={"autolearn_min_sites": 4})
    assert r.status_code == 503 and "écriture non autorisée" in r.json()["detail"]


def test_sudoers_verbe_exact():
    s = (ICI / "sudoers.d" / "secubox-adguard-tv").read_text()
    assert "/usr/sbin/secubox-adguard-tv seuils," in s or s.rstrip().endswith("/usr/sbin/secubox-adguard-tv seuils")
    assert "seuils *" not in s


def test_argv_production_sudo_exact(monkeypatch):
    monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    assert m._argv_seuils() == ["sudo", "-n", "/usr/sbin/secubox-adguard-tv", "seuils"]

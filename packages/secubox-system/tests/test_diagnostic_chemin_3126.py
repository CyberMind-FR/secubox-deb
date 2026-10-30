# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Remontée de chemin dans `download_diagnostic?name=` et `delete_diagnostic?name=` (relecture de sécurité de #3126, R-L5-14).

`Path(f"/var/lib/secubox/diagnostics/{name}")` acceptait `../../../etc/secubox/secubox.conf` : lecture (si le
fichier est du JSON) ou SUPPRESSION de tout fichier accessible au service. Le nom est désormais validé par un motif
strict et la résolution confinée au dossier des diagnostics ; un lien symbolique qui en sort est refusé."""
import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

PAQUETS = Path(__file__).resolve().parents[2]
SYSTEM = PAQUETS / "secubox-system"
sys.path.insert(0, str(PAQUETS.parent / "common"))


@pytest.fixture
def api(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("api_systeme_diag_3126", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    diag = tmp_path / "diagnostics"
    diag.mkdir()
    (diag / "rapport-1.json").write_text(json.dumps({"ok": 1}))
    (tmp_path / "secret.json").write_text(json.dumps({"jwt_secret": "x"}))
    (diag / "lien.json").symlink_to(tmp_path / "secret.json")
    monkeypatch.setattr(m, "DIAG_DIR", diag, raising=False)
    return m, diag, tmp_path


def _code(coro):
    try:
        asyncio.run(coro)
    except HTTPException as e:
        return e.status_code
    return 200


@pytest.mark.parametrize("nom", ["../secret.json", "../../etc/passwd", "/etc/passwd", "sous/rapport.json", "..",
                                 "rapport-1", "rapport-1.json\n", "", ".json", "lien.json", "a" * 200 + ".json"])
def test_nom_hors_motif_ou_hors_dossier_refuse(api, nom):
    m, diag, racine = api
    assert _code(m.download_diagnostic(name=nom, user={})) in (400, 404)
    assert _code(m.delete_diagnostic(name=nom, user={})) in (400, 404)
    assert (racine / "secret.json").exists()                  # rien n'a été supprimé hors du dossier


def test_diagnostic_du_dossier_servi_et_supprime(api):
    m, diag, _ = api
    assert asyncio.run(m.download_diagnostic(name="rapport-1.json", user={})) == {"ok": 1}
    assert asyncio.run(m.delete_diagnostic(name="rapport-1.json", user={}))["success"] is True
    assert not (diag / "rapport-1.json").exists()

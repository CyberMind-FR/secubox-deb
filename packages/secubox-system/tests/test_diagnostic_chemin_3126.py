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


def _code(appel):
    """`appel` : le résultat d'une route `def` (R-L5-16), ou une coroutine (versions précédentes)."""
    try:
        appel() if callable(appel) else asyncio.run(appel)
    except HTTPException as e:
        return e.status_code
    return 200


@pytest.mark.parametrize("nom", ["../secret.json", "../../etc/passwd", "/etc/passwd", "sous/rapport.json", "..",
                                 "rapport-1", "rapport-1.json\n", "", ".json", "lien.json", "a" * 200 + ".json"])
def test_nom_hors_motif_ou_hors_dossier_refuse(api, nom):
    m, diag, racine = api
    assert _code(lambda: m.download_diagnostic(name=nom, user={})) in (400, 404)
    assert _code(lambda: m.delete_diagnostic(name=nom, user={})) in (400, 404)
    assert (racine / "secret.json").exists()                  # rien n'a été supprimé hors du dossier


def test_diagnostic_du_dossier_servi_et_supprime(api):
    m, diag, _ = api
    assert m.download_diagnostic(name="rapport-1.json", user={}) == {"ok": 1}
    assert m.delete_diagnostic(name="rapport-1.json", user={})["success"] is True
    assert not (diag / "rapport-1.json").exists()


def test_routes_de_diagnostic_synchrones():
    """Lecture et suppression de fichiers : `def` (pool de threads), jamais sur la boucle (R-L5-16)."""
    import inspect
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location("api_sys_def", SYSTEM / "api" / "main.py"))
    m.__spec__.loader.exec_module(m)
    assert not inspect.iscoroutinefunction(m.download_diagnostic)
    assert not inspect.iscoroutinefunction(m.delete_diagnostic)


def test_diagnostic_json_invalide_rend_422(api):
    m, diag, _ = api
    (diag / "casse.json").write_text("{pas du json")
    assert _code(lambda: m.download_diagnostic(name="casse.json", user={})) == 422


def test_check_updates_et_run_diagnostic_test_en_post():
    """`check_updates` lance `apt-get update` en root (verbe de mise à jour, réservé à L2) et `run_diagnostic_test`
    exécute une commande : des actions, donc POST, pages comprises (R-L5-16)."""
    import re
    source = (SYSTEM / "api" / "main.py").read_text(encoding="utf-8")
    assert re.findall(r'@router\.(get|post)\("/check_updates"\)', source) == ["post"]
    assert re.findall(r'@router\.(get|post)\("/run_diagnostic_test"\)', source) == ["post"]
    page = (SYSTEM / "www" / "system" / "index.html").read_text(encoding="utf-8")
    assert "lire('/check_updates')" not in page and "ecrire('POST', '/check_updates')" in page
    vue = (SYSTEM / "www" / "luci-static" / "resources" / "system-hub" / "api.js").read_text(encoding="utf-8")
    assert re.findall(r"sbxFetch\('/api/v1/system/run_diagnostic_test',\s*[^,]+,\s*'([A-Z]+)'\)", vue) == ["POST"]


def test_run_diagnostic_test_lit_le_corps(monkeypatch):
    """La page portée envoie `{test: …}` dans le corps JSON (sbxFetch en POST) ; la requête reste acceptée."""
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location("api_sys_rdt", SYSTEM / "api" / "main.py"))
    m.__spec__.loader.exec_module(m)

    class Res:
        stdout, returncode = "ok", 0

    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: Res())

    class Req:
        async def json(self):
            return {"test": "disk"}

    r = asyncio.run(m.run_diagnostic_test(Req(), user={}))
    assert r["test"] == "disk" and r["success"] is True

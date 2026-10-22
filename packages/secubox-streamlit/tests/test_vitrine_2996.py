# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — `GET /apps/vitrine` : la vitrine des applis pour le Hall (nom, en ligne, domaine, vignette), lecture gardée,
sans jamais déclencher de capture."""
import json

from api import main


def test_la_vitrine_assemble_applis_instances_et_vignettes(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "_get_apps", lambda **k: [
        {"name": "bazi_calculator", "running": False}, {"name": "generix", "running": True}, {"name": "mauvais nom!", "running": True}])
    monkeypatch.setattr(main, "_load_streamlit_config", lambda: {"instances": {
        "pix": {"app": "bazi_calculator", "domain": "bazi.gk2.secubox.in", "enabled": True},
        "gx": {"app": "generix", "enabled": False}}})
    monkeypatch.setattr(main, "SHOTS_CACHE_DIR", tmp_path)
    (tmp_path / "generix").mkdir()
    (tmp_path / "generix" / "screenshot.png").write_bytes(b"png")
    (tmp_path / "generix" / "screenshot.json").write_text(json.dumps({"captured_at": "2026-08-03T07:51:24+00:00", "ok": True}))
    r = main.apps_vitrine()
    noms = [a["name"] for a in r["apps"]]
    assert noms == ["generix", "bazi_calculator"]            # en ligne d'abord, puis alphabétique ; nom invalide écarté
    g = r["apps"][0]
    assert g["running"] and g["screenshot_available"] and g["screenshot_captured_at"].startswith("2026-08-03") and g["domain"] is None
    b = r["apps"][1]
    assert b["domain"] == "bazi.gk2.secubox.in" and b["screenshot_available"] is False and b["screenshot_captured_at"] is None


def test_la_vitrine_est_en_lecture_gardee():
    routes = {r.path: r for r in main.router.routes}
    dep = routes["/apps/vitrine"].dependencies
    assert any(d.dependency is main.require_lecture for d in dep)

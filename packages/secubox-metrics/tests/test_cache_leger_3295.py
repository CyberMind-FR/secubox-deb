# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3295 — la partie légère du cache (waf, connexions) est rafraîchie en fond, sans requête."""
import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]


@pytest.fixture
def M(tmp_path, monkeypatch):
    from secubox_core import config as _c
    if _c._CONFIG is None:  # poste de dev : /etc/secubox/secubox.conf illisible
        monkeypatch.setattr(_c, "_CONFIG", {})
    from api import main as m
    monkeypatch.setattr(m, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(m, "CACHE_FILE", tmp_path / "metrics-cache.json")
    return m


def test_intervalle_borne(M, tmp_path, monkeypatch):
    conf = tmp_path / "metrics.toml"
    monkeypatch.setattr(M, "CONF", conf)
    assert M.intervalle_cache_leger() == 60
    for brut, attendu in ((1, 15), (99999, 3600), (120, 120), ("x", 60), (True, 60)):
        conf.write_text(f"[cache]\nintervalle_leger = {json.dumps(brut)}\n")
        assert M.intervalle_cache_leger() == attendu


def test_rafraichit_leger_garde_overview(M, monkeypatch):
    M.CACHE_FILE.write_text(json.dumps({"overview": {"lxc_containers": 7}, "waf": {"active_bans": 0},
                                        "timestamp_epoch": 1}))
    monkeypatch.setattr(M, "build_waf_stats", lambda: {"active_bans": 5})
    monkeypatch.setattr(M, "build_connections", lambda: {"http": 2})
    M.rafraichir_cache_leger()
    d = json.loads(M.CACHE_FILE.read_text())
    assert d["overview"] == {"lxc_containers": 7}
    assert d["waf"] == {"active_bans": 5} and d["connections"] == {"http": 2}
    assert d["timestamp_epoch"] > 1 and d["timestamp"]


def test_sans_fichier_ne_fabrique_pas_overview(M, monkeypatch):
    monkeypatch.setattr(M, "build_waf_stats", lambda: {})
    monkeypatch.setattr(M, "build_connections", lambda: {})
    M.rafraichir_cache_leger()
    assert not M.CACHE_FILE.exists()  # build_cache s'en charge (prechauffage)


def test_ecriture_atomique(M, monkeypatch):
    M.CACHE_FILE.write_text(json.dumps({"overview": {"a": 1}}))
    os.chmod(M.CACHE_FILE, 0o644)
    monkeypatch.setattr(M, "build_waf_stats", lambda: {})
    monkeypatch.setattr(M, "build_connections", lambda: {})
    vus = []
    reel = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (vus.append((str(a), str(b))), reel(a, b))[1])
    M.rafraichir_cache_leger()
    assert vus and vus[0][1] == str(M.CACHE_FILE) and vus[0][0] != vus[0][1]
    assert stat.S_IMODE(M.CACHE_FILE.stat().st_mode) == 0o644
    assert [p.name for p in M.CACHE_DIR.iterdir()] == ["metrics-cache.json"]


def test_boucle_rafraichit_sans_requete(M, monkeypatch):
    M.CACHE_FILE.write_text(json.dumps({"overview": {"a": 1}}))
    n = {"c": 0}

    def waf():
        n["c"] += 1
        return {"n": n["c"]}

    monkeypatch.setattr(M, "build_waf_stats", waf)
    monkeypatch.setattr(M, "build_connections", lambda: {})
    monkeypatch.setattr(M, "intervalle_cache_leger", lambda: 0.01)

    async def aller():
        t = asyncio.create_task(M._boucle_cache_leger())
        await asyncio.sleep(0.15)
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)

    asyncio.run(aller())
    assert n["c"] >= 3
    assert json.loads(M.CACHE_FILE.read_text())["overview"] == {"a": 1}


def test_boucle_survit_a_une_erreur(M, monkeypatch):
    n = {"c": 0}

    def casse():
        n["c"] += 1
        raise RuntimeError("x")

    monkeypatch.setattr(M, "rafraichir_cache_leger", casse)
    monkeypatch.setattr(M, "intervalle_cache_leger", lambda: 0.01)

    async def aller():
        t = asyncio.create_task(M._boucle_cache_leger())
        await asyncio.sleep(0.1)
        vivant = not t.done()
        t.cancel()
        await asyncio.gather(t, return_exceptions=True)
        return vivant

    assert asyncio.run(aller()) and n["c"] >= 2


def test_lifespan_et_amorcage_lancent_la_boucle():
    src = (PKG / "api/main.py").read_text(encoding="utf-8")
    assert src.count("_boucle_cache_leger()") >= 2  # lifespan + amorcer_collecte (agregateur)


def test_unite_sans_runtimemaxsec_et_minuterie():
    unite = (PKG / "debian/secubox-metrics.service").read_text(encoding="utf-8")
    assert not [l for l in unite.splitlines() if l.strip().startswith("RuntimeMaxSec")]
    timer = (PKG / "systemd/secubox-metrics-redemarrage.timer").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=6h" in timer and "WantedBy=timers.target" in timer
    svc = (PKG / "systemd/secubox-metrics-redemarrage.service").read_text(encoding="utf-8")
    assert "Type=oneshot" in svc and "systemctl try-restart secubox-metrics.service" in svc
    rules = (PKG / "debian/rules").read_text(encoding="utf-8")
    assert "secubox-metrics-redemarrage.timer" in rules
    assert "secubox-metrics-redemarrage.timer" in (PKG / "debian/postinst").read_text(encoding="utf-8")

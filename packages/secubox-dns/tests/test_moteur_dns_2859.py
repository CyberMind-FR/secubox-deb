# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2859 — /dns/ dit le moteur DNS RÉEL : BIND absent + Unbound actif n'est pas « DNS arrêté ».

Constat sur gk2 : « BIND ARRÊTÉ, 0 zone » alors que la résolution marche (Unbound actif). Le module est un gestionnaire de zones BIND ; quand `dnsmaster` est absent, l'API renvoyait
`running: false` par défaut, ce que la page lisait comme une panne."""
import asyncio
import json
import re
from pathlib import Path
from unittest import mock

import pytest

import secubox_core.config as _cfg

# `api.main` lit la config et crée /var/lib/secubox/dns À L'IMPORT : on isole la machine (comme test_routes_uniques_2050).
_cfg._CONFIG = {"global": {}, "api": {"socket_dir": "/tmp/secubox", "jwt_secret": "test"}, "auth": {"users": {}}}
with mock.patch("pathlib.Path.mkdir"):
    from api import main as M  # noqa: E402
PAGE = Path(__file__).resolve().parents[1] / "www" / "dns" / "index.html"


def _etat(monkeypatch, bind_json, unbound_actif):
    monkeypatch.setattr(M, "run_cmd", lambda args, capture=True: (0, json.dumps(bind_json), "") if bind_json is not None else (1, "", "dnsmaster not installed"))
    monkeypatch.setattr(M, "_unite_active", lambda nom: unbound_actif if nom == "unbound" else False)
    return asyncio.run(M.status())


def test_bind_actif_reste_bind(monkeypatch):
    r = _etat(monkeypatch, {"running": True, "zones": 2, "records": 3}, True)
    assert r["moteur"] == "bind" and r["moteur_actif"] is True and r["running"] is True and r["zones"] == 2


def test_bind_absent_et_unbound_actif_est_unbound_actif(monkeypatch):
    r = _etat(monkeypatch, None, True)
    assert r["moteur"] == "unbound" and r["moteur_actif"] is True
    assert r["running"] is False and r["zones"] == 0           # clés d'origine conservées : « running » reste l'état de BIND


def test_ni_bind_ni_unbound_est_aucun(monkeypatch):
    r = _etat(monkeypatch, None, False)
    assert r["moteur"] == "aucun" and r["moteur_actif"] is False


def test_bind_arrete_mais_unbound_actif_ne_se_fait_pas_passer_pour_bind(monkeypatch):
    r = _etat(monkeypatch, {"running": False, "zones": 1, "records": 1}, True)
    assert r["moteur"] == "unbound" and r["moteur_actif"] is True and r["running"] is False


def test_health_est_ok_si_un_moteur_repond(monkeypatch):
    monkeypatch.setattr(M, "run_cmd", lambda args, capture=True: (1, "", "absent"))
    monkeypatch.setattr(M, "_unite_active", lambda nom: nom == "unbound")
    h = asyncio.run(M.health())
    assert h["status"] == "ok" and h["running"] is False and h["moteur"] == "unbound"


playwright = pytest.importorskip("playwright.sync_api")


def test_la_page_dit_unbound_actif_et_explique_l_absence_de_zone_bind():
    src = PAGE.read_text(encoding="utf-8")
    with playwright.sync_playwright() as pw:
        try:
            nav = pw.chromium.launch()
        except Exception as e:
            pytest.skip(str(e))
        ctx = nav.new_context(viewport={"width": 1300, "height": 900})
        p = ctx.new_page()
        erreurs = []
        p.on("pageerror", lambda e: erreurs.append(str(e)))

        def fichier(r, *_):
            chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
            if chemin.startswith("shared/"):
                r.fulfill(status=200, content_type="application/javascript", body="")
            elif chemin.rstrip("/") == "dns":
                r.fulfill(status=200, content_type="text/html", body=src)
            else:
                r.fulfill(status=404, body="")
        p.route("http://sbx.test/**", fichier)
        corps = {"/status": {"running": False, "zones": 0, "records": 0, "moteur": "unbound", "moteur_actif": True}, "/zones": {"zones": []}}
        p.route("http://sbx.test/api/v1/dns/**", lambda r, *_: r.fulfill(status=200, content_type="application/json", body=json.dumps(corps.get(r.request.url.split("/api/v1/dns", 1)[1].split("?")[0], {}))))
        p.goto("http://sbx.test/dns/")
        p.wait_for_function("document.getElementById('etat').textContent !== 'Chargement…'")
        assert p.inner_text("#etat") == "UNBOUND ACTIF"
        assert p.inner_text("#tBind") == "Actif" and p.inner_text("#lBind") == "UNBOUND"
        assert re.search(r"Unbound", p.inner_text("#listeZones")) and "zone BIND" in p.inner_text("#listeZones")
        assert "hors" not in (p.get_attribute("#etat", "class") or "") and erreurs == []
        ctx.close()
        nav.close()

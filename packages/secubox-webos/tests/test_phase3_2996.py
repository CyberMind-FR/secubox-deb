# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 3) — réactivité : statut typé {active, idle, offline, stale, nosource} côté API, « Relevé HH:MM:SS »
et « données périmées » au pied des cartes v2, aperçus différés pour les modules en veille, dock média persistant."""
import json
import mimetypes
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.main as m
from api.registry import normalize_services, statut

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"

MENU = {"categories": [{"items": [
    {"id": "waf", "name": "WAF", "category": "wall", "path": "/waf/", "domain": "waf.gk2.secubox.in"},
    {"id": "radio", "name": "Radio", "category": "mind", "path": "/radio/", "same_origin": True},
    {"id": "peertube", "name": "PeerTube", "category": "mesh", "path": "/pt/", "domain": "peertube.gk2.secubox.in"},
    {"id": "lyrion", "name": "Lyrion", "category": "mind", "path": "/lyrion/"},
    {"id": "zia", "name": "ZIA", "category": "mind", "path": "/zia/"},
]}]}
HEALTH = {"waf": {"status": "ok"}, "radio": {"status": "error"}, "peertube": {"status": "ok"}, "lyrion": {"status": "warn"}}


def test_quintuplet_de_statut():
    assert statut("online", False) == "active" and statut("offline", False) == "offline"
    assert statut("degraded", False) == "stale" and statut("unknown", False) == "nosource"
    assert statut("online", True) == "idle"   # en veille prime : il répondrait une fois réveillé


def test_normalize_porte_le_statut_et_la_veille_des_profils():
    svcs = {s.id: s for s in normalize_services(MENU, HEALTH, None, endormis=frozenset({"peertube"}))}
    assert svcs["waf"].status == "active" and svcs["radio"].status == "offline"
    assert svcs["peertube"].status == "idle" and svcs["peertube"].health.state == "online"
    assert svcs["lyrion"].status == "stale" and svcs["zia"].status == "nosource"


def test_public_services_expose_statut_releve_et_intervalle(monkeypatch):
    monkeypatch.setattr(m, "_flags", {"enabled": True, "registry_enabled": True, "hall_v2": True})
    svcs = normalize_services(MENU, HEALTH, None, endormis=frozenset({"peertube"}))
    monkeypatch.setitem(m._cache, "services", [s.model_dump() for s in svcs])
    monkeypatch.setitem(m._cache, "computed_at", 1792566652.0)
    d = TestClient(m.app).get("/public/services").json()
    par = {s["id"]: s for s in d["services"]}
    assert par["peertube"]["status"] == "idle" and par["waf"]["status"] == "active" and par["zia"]["status"] == "nosource"
    assert d["releve"] == "2026-10-21T07:10:52+00:00" and d["intervalle_s"] == 15
    assert "urls" not in par["waf"]


def test_modules_endormis_lit_les_lifecycles(monkeypatch):
    from api import registry

    class Rep:
        status = 200

        def read(self):
            return json.dumps({"lifecycles": [{"id": "peertube", "sleep_state": "asleep"}, {"id": "waf", "sleep_state": "up"},
                                              {"id": "x", "sleep_state": "n/a"}]}).encode()

    class Conn:
        def __init__(self, *a, **k):
            pass

        def request(self, *a):
            pass

        def getresponse(self):
            return Rep()

        def close(self):
            pass
    monkeypatch.setattr(registry, "_ConnexionUnix", Conn)
    assert registry.modules_endormis("/nulle/part") == frozenset({"peertube"})


def test_modules_endormis_vide_si_profils_injoignables():
    from api import registry
    assert registry.modules_endormis("/run/secubox/inexistant-2996.sock") == frozenset()


# ── Rendu ──────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def services(age_s=0.0):
    return {"services": [
        {"id": "radio", "name": "Radio", "category": "mind", "icon": "R", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/radio/"},
        {"id": "peertube", "name": "PeerTube", "category": "mesh", "icon": "P", "installed": True, "active": True, "status": "idle", "health": {"state": "online"}, "path": "/pt/"},
        {"id": "acces", "name": "Accès", "category": "auth", "icon": "A", "installed": True, "active": True, "status": "offline", "health": {"state": "offline"}, "path": "/acces/"},
        {"id": "activite", "name": "Activité", "category": "mind", "icon": "V", "installed": True, "active": True, "status": "stale", "health": {"state": "degraded"}, "path": "/activite/"},
    ], "computed_at": time.time() - age_s, "releve": "2026-10-21T07:10:52+00:00", "intervalle_s": 15}


def ouvre(nav, age_s=0.0):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(services(age_s)))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.16.0-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        if u.startswith("/pt/") or "peertube" in r.request.url:
            return r.fulfill(status=200, content_type="text/html", body="<p>pt</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".fcard[data-status]", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def test_statut_type_sur_chaque_carte_et_releve_au_pied(nav):
    ctx, p, erreurs = ouvre(nav)
    statuts = p.evaluate("Object.fromEntries([...document.querySelectorAll('.fcard[data-embed]')].map(c=>[c.getAttribute('data-embed'), c.getAttribute('data-status')]))")
    assert statuts.get("radio") == "active" and statuts.get("peertube") == "idle" and statuts.get("acces") == "offline"
    assert statuts.get("activite") == "stale" and statuts.get("comptes") == "nosource"   # absent du registre → aucune source
    pied = p.inner_text(".fcard[data-embed=radio] .sbx-fcard-pied")
    assert re.fullmatch(r"Relevé \d{2}:\d{2}:\d{2}", pied), pied
    assert "en veille" in p.inner_text(".fcard[data-embed=peertube] .sbx-fcard-pied")
    # l'opacité découle du statut, jamais codée en dur dans le JS
    op = {k: float(p.evaluate("getComputedStyle(document.querySelector('.fcard[data-embed=%s]')).opacity" % k)) for k in ("radio", "acces", "comptes")}
    assert op["radio"] == 1 and op["acces"] < 1 and op["comptes"] < 1
    assert erreurs == []
    ctx.close()


def test_donnees_perimees_au_dela_de_deux_intervalles(nav):
    ctx, p, erreurs = ouvre(nav, age_s=100)
    assert p.inner_text(".fcard[data-embed=radio] .sbx-fcard-pied").startswith("données périmées")
    assert p.evaluate("document.querySelector('.fcard[data-embed=radio]').getAttribute('data-perime')") == "1"
    assert erreurs == []
    ctx.close()


def test_module_en_veille_sans_requete_et_dock_persistant(nav):
    ctx, p, erreurs = ouvre(nav)
    # PeerTube (idle) : son aperçu ne porte plus de src, la note de veille est posée
    assert p.evaluate("[...document.querySelectorAll('.fcard[data-embed=peertube] iframe')].every(f=>!f.getAttribute('src'))")
    assert p.evaluate("!!document.querySelector('.fcard[data-embed=peertube] .sbx-veille')")
    # le dock média est le même nœud avant et après une navigation interne
    p.evaluate("window.__dock=document.getElementById('mediadock'); true")
    p.evaluate("showView('systeme')")
    p.evaluate("showView('accueil')")
    assert p.evaluate("document.getElementById('mediadock')===window.__dock")
    assert erreurs == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — vignettes des modules : file de capture (une par tour, charge, verrou, empreinte hebdomadaire), route statique
nginx, champ `vignette` du registre public, tuile de la mosaïque avec image."""
import asyncio
import json
import mimetypes
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.main as m
from api import vignettes
from secubox_core import screenshots, shotter

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
PNG = b"\x89PNG\r\n\x1a\n" + bytes.fromhex("0000000d4948445200000001000000010806000000" "1f15c489" "0000000a49444154789c6300010000050001" "0d0a2db4" "0000000049454e44ae426082")

SERVICES = [
    {"id": "radio", "urls": {"lan": "https://radio.sbx.test", "path": "/radio/"}, "routing": {"available": True}, "health": {"state": "online"}},
    {"id": "waf", "urls": {"lan": "https://waf.sbx.test", "path": "/waf/"}, "routing": {"available": True}, "health": {"state": "online"}},
    {"id": "bbs", "urls": {"lan": "https://bbs.sbx.test", "path": "/bbs/"}, "routing": {"available": False}, "health": {"state": "offline"}},
    {"id": "dpi", "urls": {"lan": None, "path": "/dpi/"}, "routing": {"available": True}, "health": {"state": "online"}},
]


def test_candidats_un_vhost_public_joignable_seulement():
    assert vignettes.candidats(SERVICES) == [("radio", "radio.sbx.test"), ("waf", "waf.sbx.test")]


def test_empreinte_hebdomadaire():
    assert vignettes.fingerprint("radio.sbx.test", date(2026, 10, 21)) == "radio.sbx.test@2026-W43"
    assert vignettes.fingerprint("radio.sbx.test", date(2026, 10, 26)) != vignettes.fingerprint("radio.sbx.test", date(2026, 10, 21))


def test_pick_next_manquante_puis_ratee_puis_rien(tmp_path):
    jour = date(2026, 10, 21)
    assert vignettes.pick_next(SERVICES, tmp_path, jour) == ("radio", "radio.sbx.test")
    screenshots.record(tmp_path, "radio", PNG, vignettes.fingerprint("radio.sbx.test", jour), ok=True)
    assert vignettes.pick_next(SERVICES, tmp_path, jour) == ("waf", "waf.sbx.test")
    # une tentative ratée garde la file ouverte mais passe derrière ce qui n'a jamais été tenté
    screenshots.record(tmp_path, "waf", None, vignettes.fingerprint("waf.sbx.test", jour), ok=False)
    assert vignettes.pick_next(SERVICES, tmp_path, jour) == ("waf", "waf.sbx.test")
    screenshots.record(tmp_path, "waf", PNG, vignettes.fingerprint("waf.sbx.test", jour), ok=True)
    assert vignettes.pick_next(SERVICES, tmp_path, jour) is None
    # la semaine suivante, tout est à reprendre
    assert vignettes.pick_next(SERVICES, tmp_path, date(2026, 10, 28)) == ("radio", "radio.sbx.test")
    assert vignettes.vignettes_presentes(["radio", "waf", "bbs"], tmp_path) == {"radio", "waf"}


def test_capture_module_enregistre_et_un_echec_garde_l_ancienne(tmp_path):
    async def ok(url):
        assert url == "https://radio.sbx.test/?theme=dark&embed=1"
        return PNG

    async def ko(url):
        raise shotter.ShotError("boum")
    oui = lambda u: (True, "Radio")  # noqa: E731
    r = asyncio.run(vignettes.capture_module("radio", "radio.sbx.test", tmp_path, _capture=ok, _sonde=oui))
    assert r["ok"] and screenshots.png_path(tmp_path, "radio").read_bytes() == PNG
    r = asyncio.run(vignettes.capture_module("radio", "radio.sbx.test", tmp_path, _capture=ko, _sonde=oui))
    assert r["ok"] is False and "boum" in r["error"]
    assert screenshots.png_path(tmp_path, "radio").read_bytes() == PNG


def test_sans_page_reelle_chromium_ne_demarre_pas_et_le_module_est_ecarte_pour_la_semaine(tmp_path):
    appels = []

    async def jamais(url):
        appels.append(url)
        return PNG
    non = lambda u: (False, "http 421")  # noqa: E731
    r = asyncio.run(vignettes.capture_module("waf", "waf.sbx.test", tmp_path, _capture=jamais, _sonde=non))
    assert r["sans_page"] and not appels and not screenshots.png_path(tmp_path, "waf").exists()
    fp = vignettes.fingerprint("waf.sbx.test")
    assert vignettes.sans_page_frais(tmp_path, "waf", fp) and not vignettes.sans_page_frais(tmp_path, "waf", "autre")
    assert vignettes.pick_next([SERVICES[1]], tmp_path) is None     # écarté ce tour-ci et jusqu'à la semaine prochaine
    assert vignettes.pick_next([SERVICES[1]], tmp_path, date(2027, 1, 6)) == ("waf", "waf.sbx.test")


def test_module_non_route_par_le_waf_ecarte_sans_aucune_requete_3174(tmp_path):
    """#3174 : la sonde d'un nom non routé laissait une anomalie dans le journal des menaces du WAF ; la table de routes le dit d'avance."""
    sondes, captures = [], []

    def sonde(url):
        sondes.append(url)
        return True, "Page"

    async def capture(url):
        captures.append(url)
        return PNG
    r = asyncio.run(vignettes.capture_module("dpi", "dpi.sbx.test", tmp_path, _capture=capture, _sonde=sonde, _routes=lambda: {"radio.sbx.test"}))
    assert r["sans_page"] and "non routé" in r["error"] and not sondes and not captures
    assert vignettes.sans_page_frais(tmp_path, "dpi", vignettes.fingerprint("dpi.sbx.test"))
    r = asyncio.run(vignettes.capture_module("radio", "Radio.sbx.test", tmp_path, _capture=capture, _sonde=sonde, _routes=lambda: {"radio.sbx.test"}))
    assert r["ok"] and len(sondes) == 1                                                # routé : sondé puis capturé
    r = asyncio.run(vignettes.capture_module("bbs", "bbs.sbx.test", tmp_path, _capture=capture, _sonde=sonde, _routes=lambda: None))
    assert r["ok"] and len(sondes) == 2                                                # sans table : comme avant


def test_la_sonde_refuse_421_erreur_et_connexion(monkeypatch):
    import io

    class Rep(io.BytesIO):
        def __init__(self, status, corps):
            super().__init__(corps)
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    reponses = {"https://a/": Rep(200, b"<html><title>421 \xc2\xb7 Requ\xc3\xaate mal aiguill\xc3\xa9e</title>"),
                "https://b/": Rep(200, b"<html><title>SecuBox \xe2\x80\x94 Connexion</title>"),
                "https://c/": Rep(200, b"<html><title>SBXWAF \xe2\x80\x94 le pare-feu</title><body>ok</body>"),
                "https://d/": Rep(503, b"")}
    monkeypatch.setattr(vignettes.urllib.request, "urlopen", lambda req, timeout, context: reponses[req.full_url])
    assert vignettes.sonde("https://a/", ca=None)[0] is False
    assert vignettes.sonde("https://b/", ca=None)[0] is False
    assert vignettes.sonde("https://c/", ca=None) == (True, "SBXWAF — le pare-feu")
    assert vignettes.sonde("https://d/", ca=None) == (False, "http 503")


def test_verrou_et_garde_de_charge(tmp_path, monkeypatch):
    fh = vignettes.acquire_lock(tmp_path / ".lock")
    assert fh is not None and vignettes.acquire_lock(tmp_path / ".lock") is None
    fh.close()
    monkeypatch.setattr(vignettes.os, "getloadavg", lambda: (9.0, 1.0, 1.0))
    assert vignettes.load_ok(4.0) is False
    monkeypatch.setattr(vignettes.os, "getloadavg", lambda: (3.0, 1.0, 1.0))
    assert vignettes.load_ok(4.0) is True


def test_registre_public_porte_vignette_et_nginx_la_sert_en_statique(monkeypatch):
    monkeypatch.setattr(m, "_flags", {"enabled": True, "registry_enabled": True, "hall_v2": True})
    monkeypatch.setitem(m._cache, "services", [m.Service(id="radio", name="Radio", category="mind", urls={"path": "/radio/"}, routing={}, health={}, auth={}, vignette=True).model_dump(),
                                              m.Service(id="waf", name="WAF", category="wall", urls={"path": "/waf/"}, routing={}, health={}, auth={}).model_dump()])
    monkeypatch.setitem(m._cache, "computed_at", 1.0)
    par = {s["id"]: s for s in TestClient(m.app).get("/public/services").json()["services"]}
    assert par["radio"]["vignette"] is True and par["waf"]["vignette"] is False
    conf = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
    assert 'location ~ "^/api/v1/webos/public/vignette/([a-z0-9][a-z0-9_-]*)$"' in conf
    assert "alias /var/cache/secubox/webos/shots/$1/screenshot.png;" in conf
    rules = (PKG / "debian" / "rules").read_text(encoding="utf-8")
    assert "sbin/webos-vignettes" in rules and "secubox-webos-vignettes.timer" in rules
    assert "secubox-webos-vignettes.timer" in (PKG / "debian" / "postinst").read_text(encoding="utf-8")
    unite = (PKG / "debian" / "secubox-webos-vignettes.service").read_text(encoding="utf-8")
    for ligne in ("User=secubox", "NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/var/cache/secubox/webos", "CPUQuota=20%", "Nice=19"):
        assert ligne in unite, ligne
    assert "Recommends:" in (PKG / "debian" / "control").read_text(encoding="utf-8") and "chromium" in (PKG / "debian" / "control").read_text(encoding="utf-8")


playwright = pytest.importorskip("playwright.sync_api")


def test_la_tuile_de_la_mosaique_montre_la_vignette():
    services = {"services": [
        {"id": "radio", "name": "Radio", "category": "mind", "icon": "R", "installed": True, "active": True, "status": "active", "vignette": True, "health": {"state": "online"}, "path": "/radio/"},
        {"id": "waf", "name": "WAF", "category": "wall", "icon": "W", "installed": True, "active": True, "status": "active", "vignette": False, "health": {"state": "online"}, "path": "/waf/"},
    ], "computed_at": 1792566652.0, "releve": "2026-10-21T07:10:52+00:00", "intervalle_s": 15}
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        p = b.new_page(viewport={"width": 1440, "height": 900})
        erreurs = []
        p.on("pageerror", lambda e: erreurs.append(str(e)))

        def sert(r):
            u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
            if u == "/api/v1/webos/public/services":
                return r.fulfill(status=200, content_type="application/json", body=json.dumps(services))
            if u == "/api/v1/webos/public/vignette/radio":
                return r.fulfill(status=200, content_type="image/png", body=PNG)
            if u.startswith("/api/"):
                return r.fulfill(status=401, content_type="application/json", body="{}")
            f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes()) if f.is_file() else r.fulfill(status=404, body="")
        p.route("http://sbx.test/**", sert)
        p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
        p.goto("http://sbx.test/?hall=v2")
        p.wait_for_selector(".fcard[data-status]", state="attached")
        p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
        p.click(".sbx-side .sbx-rub[data-rub='modules']")
        p.wait_for_selector("#view-mosaique .sbx-mtuile[data-module=radio] .vig img", state="attached")
        assert p.evaluate("document.querySelector('#view-mosaique .sbx-mtuile[data-module=radio] .vig img').getAttribute('src')") == "/api/v1/webos/public/vignette/radio"
        assert p.evaluate("!document.querySelector('#view-mosaique .sbx-mtuile[data-module=waf] .vig')")
        assert erreurs == []
        b.close()

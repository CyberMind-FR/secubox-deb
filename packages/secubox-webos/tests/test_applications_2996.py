# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4) — rubrique « Applications » de la mosaïque : les applis Streamlit et leurs vignettes, lues par deux
relais du vhost du Hall sous session SecuBox (décision #1776 : une vignette photographie l'appli, jamais à un anonyme).
Tuile = lien vers le domaine de l'appli quand elle en a un, sinon bouton vers la console Streamlit embarquée. Sans session,
la mosaïque le dit au lieu de rester vide."""
import json
import mimetypes
import re
import struct
import time
import zlib
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")

def _png_1x1() -> bytes:
    """Un vrai PNG d'un pixel : une image invalide déclencherait `error` et la tuile retirerait sa vignette."""
    def bloc(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return b"\x89PNG\r\n\x1a\n" + bloc(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + bloc(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + bloc(b"IEND", b"")


PNG = _png_1x1()
VITRINE = {"apps": [
    {"name": "generix", "running": True, "archived": False, "domain": None, "screenshot_available": True, "screenshot_captured_at": "2026-08-03T07:51:24+00:00"},
    {"name": "bazi_calculator", "running": False, "archived": False, "domain": "bazi.gk2.secubox.in", "screenshot_available": False, "screenshot_captured_at": None},
    {"name": "vieille", "running": False, "archived": True, "domain": None, "screenshot_available": False, "screenshot_captured_at": None},
], "vhost_suffix": "gk2.secubox.in"}


def test_relais_sous_session_et_rubrique_declaree():
    m = re.search(r'location ~ "\^/api/v1/streamlit/apps/\(vitrine\|\[A-Za-z0-9_\.-\]\{1,64\}/screenshot\)\\z" \{(.*?)\n    \}', VHOST, re.S)
    assert m, "relais Streamlit absent"
    assert "auth_request /__sbx_verifie_secubox" in m.group(1) and "limit_except GET" in m.group(1) and "streamlit.sock" in m.group(1)
    assert "{id:'apps',nom:'Applications'" in JS and "function tuileApp(" in JS


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, session=True):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps({"services": [{"id": "streamlit", "status": "active"}], "computed_at": time.time(), "intervalle_s": 15}))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.21-1", "en_ligne": true}')
        if u == "/api/v1/streamlit/apps/vitrine":
            return r.fulfill(status=200 if session else 401, content_type="application/json", body=json.dumps(VITRINE if session else {}))
        if u.startswith("/api/v1/streamlit/apps/") and u.endswith("/screenshot"):
            return r.fulfill(status=200, content_type="image/png", body=PNG)
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith(("/cardlets/", "/guardian/", "/dpi-vue/", "/actor-intelligence/")):
            return r.fulfill(status=200, content_type="text/html", body="<p>x</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".sbx-side .sbx-rub[data-rub='apps']", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    p.click(".sbx-side .sbx-rub[data-rub='apps']")
    return ctx, p, erreurs


def test_la_rubrique_montre_les_applis_avec_vignette_lien_ou_console(nav):
    ctx, p, erreurs = ouvre(nav)
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mosaique[data-vue='apps'] .sbx-atuile", state="attached")
    assert p.inner_text("#view-mosaique .sbx-mosaique-titre") == "Applications"
    t = p.evaluate("[...document.querySelectorAll('.sbx-mosaique .sbx-atuile')].map(e=>[e.tagName,e.getAttribute('href'),e.getAttribute('data-open'),e.getAttribute('data-status'),!!e.querySelector('.vig img'),e.querySelector('b').textContent])")
    assert len(t) == 2, t                                   # l'archivée n'est pas montrée
    assert t[0] == ["BUTTON", None, "streamlit", "active", True, "generix"]       # pas de domaine : console Streamlit embarquée
    assert t[1] == ["A", "https://bazi.gk2.secubox.in/", None, "idle", False, "bazi_calculator"]
    src = p.evaluate("document.querySelector('.sbx-mosaique .sbx-atuile .vig img').getAttribute('src')")
    assert src.startswith("/api/v1/streamlit/apps/generix/screenshot?t=2026-08-03")
    assert "2 applications" in p.inner_text("#view-mosaique .sbx-mosaique-compte")
    assert erreurs == []
    ctx.close()


def test_sans_session_la_mosaique_le_dit(nav):
    ctx, p, erreurs = ouvre(nav, session=False)
    p.wait_for_selector("#view-mosaique .sbx-mosaique-vide:not([hidden])", state="attached")
    assert "session" in p.inner_text("#view-mosaique .sbx-mosaique-vide")
    assert p.evaluate("document.querySelectorAll('.sbx-mosaique .sbx-atuile').length") == 0
    assert erreurs == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2646 — /zia/ (chat plein cadre) au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "zia"
SRC = (WWW / "index.html").read_text(encoding="utf-8")
VOIX = (WWW / "voix.js").read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["voix.js", "/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'zia'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_appels_a_l_identique():
    assert "API + '/v1/chat'" in SRC and "method: 'POST'" in SRC and "'Content-Type': 'application/json'" in SRC
    assert "JSON.stringify({ message: m })" in SRC and "API + '/health'" in SRC
    for msg in ("sbx: 'ouvre'", "sbx: 'voir'", "sbx: 'ouvre-hote'"):
        assert msg in SRC
    assert "ZIAVoix.init" in SRC and "ZIAVoix.dit" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


REPONSE = {"text": "Voici **la vidéo** <i>x</i> ❤", "engine": "llm", "trace": [{"tool": "chercher", "args": {"q": "waf"}}],
           "objects": [{"service": "podcaster", "type": "media.video", "title": "Le WAF", "summary": "résumé", "uri": "sbx://p/1",
                        "url": "https://x.example.test/v", "actions": ["open", "play"]}],
           "delegate": {"to": "podcaster"}}
HEALTH = {"model": "TinyLlama", "engine": "llm"}
URL = "http://sbx.test/zia/"


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin == "zia/voix.js":
            r.fulfill(status=200, content_type="application/javascript", body=VOIX)
        elif chemin.rstrip("/") == "zia":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/zia", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/zia/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_chat_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, {"/health": (200, HEALTH), "/v1/chat": (200, REPONSE)})
    p.wait_for_function("document.getElementById('etat').textContent === 'EN LIGNE'")
    assert [p.inner_text(i) for i in ("#eng", "#mdl", "#tEchanges")] == ["modèle", "TinyLlama", "0"]
    p.fill("#q", "trouve le waf")
    p.press("#q", "Enter")
    p.wait_for_selector("#stream .obj")
    assert json.loads([a for a in appels if a[1] == "/v1/chat"][0][2]) == {"message": "trouve le waf"}
    assert p.inner_text("#tEchanges") == "1"
    assert p.locator("#stream .bub b").first.inner_text() == "la vidéo"
    assert "<i>x</i>" in p.inner_text("#stream") and p.locator("#stream .bub i").count() == 0   # jamais interprété
    assert "podcaster" in p.inner_text("#stream .deleg") and "chercher" in p.inner_text("#stream .trace")
    assert p.locator("#stream .obj-a button").count() == 2
    assert err == []
    ctx.close()


def test_service_injoignable_hors_ligne_et_message(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert p.inner_text("#eng") == "—" and p.inner_text("#mdl") == "—"
    p.fill("#q", "salut")
    p.press("#q", "Enter")
    p.wait_for_function("document.getElementById('stream').textContent.includes('Service ZIA injoignable.')")
    assert err == []
    ctx.close()


def test_suggestion_envoie_un_message(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {"/health": (200, HEALTH), "/v1/chat": (200, {"text": "ok"})})
    p.wait_for_selector("#sugg button")
    p.click("#sugg button >> nth=1")
    p.wait_for_function("document.getElementById('stream').textContent.includes('ok')")
    assert json.loads([a for a in appels if a[1] == "/v1/chat"][0][2]) == {"message": "les podcasts"}
    ctx.close()


def test_demonstration_annoncee_et_aucun_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#stream .msg")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.fill("#q", "test")
    p.press("#q", "Enter")
    p.wait_for_selector("#stream .obj")
    assert appels == [] and err == [] and p.locator(".zia-micro").count() == 0
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#stream .msg")
    p.fill("#q", "bonjour")
    p.press("#q", "Enter")
    p.wait_for_selector("#stream .obj")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


# ── #3074 : les actions validées repartent vers le Hall ───────────────────────
ACTION = {"kind": "sbx-action", "target": "service:radio", "service": "radio", "action": "media.play", "params": {},
          "effet": "media"}


def test_actions_relayees_au_hall_quand_la_page_est_embarquee(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    hote = "<!doctype html><script>window.recus=[];addEventListener('message',e=>{if(e.data&&e.data.sbx==='action')recus.push(e.data.req)})</script><iframe id=f src='http://sbx.test/zia/?embed=1' width=900 height=700></iframe>"

    def tout(r, *_):
        u = r.request.url
        if "/api/v1/zia/v1/chat" in u:
            r.fulfill(status=200, content_type="application/json", body=json.dumps({"text": "Je lance radio.", "actions": [ACTION]}))
        elif "/api/v1/zia/" in u:
            r.fulfill(status=200, content_type="application/json", body=json.dumps(HEALTH))
        elif u.startswith("http://hall.test/"):
            r.fulfill(status=200, content_type="text/html", body=hote)
        elif "/zia/voix.js" in u:
            r.fulfill(status=200, content_type="application/javascript", body=VOIX)
        elif "/zia/" in u:
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=200, body="")
    ctx.route("**/*", tout)
    p.goto("http://hall.test/")
    f = p.frame_locator("#f")
    f.locator("#q").fill("Activez la radio.")
    f.locator("#q").press("Enter")
    p.wait_for_function("window.recus.length > 0")
    assert p.evaluate("window.recus")[0]["action"] == "media.play"
    assert "radio · media.play" in f.locator("#stream").inner_text()
    ctx.close()

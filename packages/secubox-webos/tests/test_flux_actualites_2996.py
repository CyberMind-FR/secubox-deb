# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4) — « Flux d'actualités » : une Card native qui fusionne MetaNews (sujets), les listes YouTube du compte
(ytsas, session) et les Billets publics en `NewsItem`, en tourniquet entre les sources, neuf entrées au plus, rafraîchie
toutes les 15 min. Les sujets et les billets sont lus en même origine par deux relais nginx du vhost du Hall (lecture seule,
données publiques) ; les vignettes MetaNews passent par son relais d'image. Les trois anciennes cartes restent (le prompt :
« sans retirer l'ancien tant que le nouveau n'est pas validé »)."""
import json
import mimetypes
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")

TOPICS = {"ok": True, "topics": [
    {"id": "mn_1", "title": "Sujet un", "summary": "…", "updated_at": int(time.time()) - 600, "sources_count": 5,
     "source_names": ["L'Humanité", "Le Monde"], "vignette": "https://exemple.test/a.jpg"},
    {"id": "mn_2", "title": "Sujet deux", "summary": "…", "updated_at": int(time.time()) - 7200, "sources_count": 2,
     "source_names": ["BFMTV"], "vignette": ""},
]}
FEED = {"version": "https://jsonfeed.org/version/1.1", "items": [
    {"id": "http://x/b/premier-billet", "url": "http://x/b/premier-billet", "title": "Premier billet",
     "date_published": "2026-10-16T04:27:56Z", "summary": "gk2", "content_html": "<p><img src=\"/media/01.png\"></p>"},
]}
FLUX = {"type": "abonnements", "items": [
    {"id": "Y_LntqDuYCg", "titre": "Une vidéo", "chaine": "Associated Press", "url": "https://www.youtube.com/watch?v=Y_LntqDuYCg",
     "vignette": "/api/v1/ytsas/flux/vignette/Y_LntqDuYCg"},
]}


def test_relais_nginx_lecture_seule_pour_les_sujets_et_les_billets():
    m = re.search(r"location ~ \^/api/v1/metanews/\(topics\|img\)\$ \{(.*?)\n    \}", VHOST, re.S)
    assert m and "limit_except GET" in m.group(1) and "metanews.sock" in m.group(1)
    b = re.search(r"location = /api/v1/billets/feed\.json \{(.*?)\n    \}", VHOST, re.S)
    assert b and "limit_except GET" in b.group(1) and "billets.sock:/feed.json" in b.group(1)
    assert "function fluxActualites(" in JS
    assert "15*60*1000" in JS or "900000" in JS      # rafraîchissement ≤ 15 min (brief, phase 3)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur=1440, v2=True, flux_code=200):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    appels = []

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        appels.append(u)
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps({"services": [], "computed_at": time.time(), "intervalle_s": 15}))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.16-1", "en_ligne": true}')
        if u == "/api/v1/metanews/topics":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(TOPICS))
        if u == "/api/v1/billets/feed.json":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(FEED))
        if u == "/api/v1/ytsas/flux":
            return r.fulfill(status=flux_code, content_type="application/json", body=json.dumps(FLUX if flux_code == 200 else {}))
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith(("/cardlets/", "/guardian/", "/dpi-vue/", "/actor-intelligence/")):
            return r.fulfill(status=200, content_type="text/html", body="<p>cardlet</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/" + ("?hall=v2" if v2 else ""))
    p.wait_for_selector(".fcard[data-embed]", state="attached")
    if v2:
        p.wait_for_selector(".sbx-flux .sbx-news", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs, appels


def test_la_carte_fusionne_les_trois_sources_en_tourniquet(nav):
    ctx, p, erreurs, appels = ouvre(nav)
    c = "#view-accueil .sbx-card.sbx-flux"
    assert p.inner_text(c + " .sbx-card-titre") == "Flux d’actualités"
    assert p.evaluate("document.querySelector(\"%s\").previousElementSibling.classList.contains('sbx-acces')" % c)
    items = p.evaluate("[...document.querySelectorAll(\"%s .sbx-news\")].map(a=>[a.href,a.target,a.rel,a.querySelector('b').textContent,a.querySelector('.sbx-news-meta').textContent])" % c)
    assert 1 <= len(items) <= 9
    titres = [i[3] for i in items]
    assert titres[:3] == ["Sujet un", "Une vidéo", "Premier billet"], titres     # tourniquet MetaNews → YouTube → Billets
    for href, cible, rel, _, meta in items:
        assert cible == "_blank" and "noopener" in rel and meta
    assert items[0][4].startswith("MetaNews")
    assert items[1][4].startswith("YouTube")
    assert items[2][4].startswith("Billets")
    # un billet mène au vhost des billets (pas à l'origine du relais), un sujet à MetaNews
    assert re.match(r"https://billets\.[^/]+/b/premier-billet$", items[2][0]), items[2][0]
    assert re.match(r"https://metanews\.", items[0][0]), items[0][0]
    # la vignette MetaNews passe par son relais d'image en même origine (CSP img-src 'self')
    vig = p.evaluate("document.querySelector(\"%s .sbx-news .sbx-news-vignette\").style.backgroundImage" % c)
    assert "/api/v1/metanews/img?u=" in vig and "exemple.test" in vig
    # la pastille dit « actif » et le pied nomme les sources
    assert p.evaluate("document.querySelector(\"%s .sbx-card-statut\").textContent" % c) == "actif"
    assert "MetaNews" in p.inner_text(c + " .sbx-source")
    # les anciennes cartes ne sont pas retirées
    assert p.evaluate("document.querySelector(\".fcard[data-embed='metanews']\")") is not None
    assert erreurs == []
    ctx.close()


def test_sans_session_youtube_est_simplement_absent(nav):
    ctx, p, erreurs, appels = ouvre(nav, flux_code=401)
    titres = p.evaluate("[...document.querySelectorAll('.sbx-flux .sbx-news b')].map(b=>b.textContent)")
    assert "Une vidéo" not in titres and "Sujet un" in titres and "Premier billet" in titres
    assert erreurs == []
    ctx.close()


def test_mobile_390_sans_debordement(nav):
    ctx, p, erreurs, appels = ouvre(nav, 390)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert erreurs == []
    ctx.close()


def test_hall_v1_sans_flux_fusionne(nav):
    ctx, p, erreurs, appels = ouvre(nav, v2=False)
    assert p.evaluate("document.querySelector('.sbx-flux')") is None
    assert "/api/v1/metanews/topics" not in appels
    assert erreurs == []
    ctx.close()

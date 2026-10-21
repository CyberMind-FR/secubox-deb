# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 2) — composants de la vue maître (window.SbxUI) et Hero vivant dans l'accueil v2.

Card, Pill, StatRing, Sparkline, Tabs, Tile, ModuleTile, NewsItem, DeviceRow, Hero : nœuds DOM, icônes SVG,
textes par textContent, statuts {active, idle, offline, stale, nosource}. Le Hero lit /public/systeme toutes
les 5 s (CPU, mémoire, stockage, réseau, E/S disque) et le titre radio.
"""
import json
import mimetypes
import os
import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "composants.js").read_text(encoding="utf-8")
CSS = (HALL_DIR / "composants.css").read_text(encoding="utf-8")
SRC = (HALL_DIR / "index.html").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
CAPTURES = os.environ.get("SBX_CAPTURES")


def test_fichiers_routes_et_budget():
    for nom in ("composants.js", "composants.css"):
        assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in (HALL_DIR / nom).read_text(encoding="utf-8")
        assert f"www/hall/{nom} $(CURDIR)/debian/secubox-webos/usr/share/secubox/www/hall/{nom}" in RULES
        for conf in ("nginx/hall-racine.conf", "nginx/webos.conf"):
            assert f"location = /{nom}" in (PKG / conf).read_text(encoding="utf-8"), (nom, conf)
    assert '<link rel="stylesheet" href="/composants.css">' in SRC
    total = sum((HALL_DIR / n).stat().st_size for n in ("tokens.css", "hall-v2.css", "composants.css"))
    assert total < 60 * 1024, total


def test_pas_d_emoji_ni_de_donnee_en_innerhtml():
    assert not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", JS + CSS)
    # innerHTML seulement pour les tracés SVG internes (ICONES), jamais pour un texte venu des données
    for m in re.finditer(r"\.innerHTML\s*=\s*([^;]+);", JS):
        assert "ICONES" in m.group(1), m.group(0)
    for composant in ("Card", "Pill", "StatRing", "Sparkline", "Tabs", "Tile", "ModuleTile", "NewsItem", "DeviceRow", "Hero"):
        assert f"function {composant}(" in JS, composant
    for statut in ("active", "idle", "offline", "stale", "nosource"):
        assert f"{statut}:" in JS and f'[data-status="{statut}"]' in CSS or statut == "active", statut


# ── Rendu ──────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs, compteur = [], {"n": 0}
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def systeme():
        compteur["n"] += 1
        n = compteur["n"]
        return {"hote": "sbx", "releve": "2026-10-21T08:00:00+00:00", "cpu_pct": 42.0 if n > 1 else None, "charge": [0.5, 0.4, 0.3], "coeurs": 4,
                "mem": {"total_mb": 4096, "used_mb": 1024, "pct": 25.0}, "disque": {"chemin": "/", "total_mb": 60000, "used_mb": 54000, "pct": 90.0},
                "reseau": {"rx_o": 1_000_000 * n, "tx_o": 500_000 * n, "t": 1000.0 + 5 * n}, "es": {"lu_o": 2_000_000 * n, "ecrit_o": 100_000 * n, "t": 1000.0 + 5 * n},
                "uptime_s": 3600}

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.15.0-1", "en_ligne": true}')
        if u == "/api/v1/webos/public/systeme":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(systeme()))
        if u == "/api/v1/webos/public/cardlets/radio":
            return r.fulfill(status=200, content_type="application/json",
                             body='{"status":"online","silence":false,"content":{"title":"Sade - No Ordinary Love","subtitle":"Sade"}}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector("#view-accueil > .sbx-hero", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def test_hero_en_tete_de_l_accueil_avec_cinq_statistiques_vivantes(nav):
    ctx, p, erreurs = ouvre(nav, 1440)
    assert p.evaluate("document.getElementById('view-accueil').firstElementChild.classList.contains('sbx-hero')")
    assert p.inner_text(".sbx-hero h2").startswith(("Bonjour", "Bonsoir"))
    assert re.fullmatch(r"\d{2}:\d{2}:\d{2}", p.inner_text(".sbx-hero-heure"))
    libelles = p.evaluate("[...document.querySelectorAll('.sbx-hero-stat .sbx-libelle')].map(e=>e.textContent)")
    assert libelles == ["Processeur", "Mémoire", "Stockage", "Réseau", "E/S disque"]
    p.wait_for_function("document.querySelectorAll('.sbx-hero .sbx-ring')[1].textContent.trim()==='25%'")
    assert p.evaluate("document.querySelectorAll('.sbx-hero .sbx-ring')[2].getAttribute('data-ton')") == "off"   # 90 % → off
    assert "1.0 Go / 4.0 Go" in p.inner_text(".sbx-hero") or "1.0 Go / 4.0 Go".replace(".", ",") in p.inner_text(".sbx-hero")
    p.wait_for_function("document.querySelector('.sbx-hero-radio b') && document.querySelector('.sbx-hero-radio b').textContent.includes('Sade')")
    # l'horloge avance
    h1 = p.inner_text(".sbx-hero-heure")
    p.wait_for_function("document.querySelector('.sbx-hero-heure').textContent!==%r" % h1, timeout=3000)
    # deuxième relevé (forcé) : CPU connu, réseau et E/S calculés par différence → sparklines non nulles
    p.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
    p.wait_for_function("document.querySelectorAll('.sbx-hero .sbx-ring')[0].textContent.trim()==='42%'", timeout=8000)
    p.wait_for_function("[...document.querySelectorAll('.sbx-hero .sbx-spark')].every(s=>[...s.querySelectorAll('li i.a')].some(i=>parseFloat(i.style.getPropertyValue('--h'))>0) && [...s.querySelectorAll('li i.b')].some(i=>parseFloat(i.style.getPropertyValue('--h'))>0))", timeout=8000)
    assert "↓" in p.inner_text(".sbx-hero") and "lu " in p.inner_text(".sbx-hero")
    # deux séries, deux couleurs : entrant/lu en accent, sortant/écrit en vert
    ca, cb = p.evaluate("(()=>{const a=document.querySelector('.sbx-hero .sbx-spark li i.a'),b=document.querySelector('.sbx-hero .sbx-spark li i.b');return [getComputedStyle(a).backgroundColor,getComputedStyle(b).backgroundColor]})()")
    assert ca != cb
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-hero .sbx-in b')).color") == ca
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-hero .sbx-out b')).color") == cb
    assert p.evaluate("document.querySelector('.sbx-hero').getBoundingClientRect().height") >= 148
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "hall-v2-1440-hero.png"))
    assert erreurs == []
    ctx.close()


def test_catalogue_des_composants(nav):
    ctx, p, erreurs = ouvre(nav, 1440)
    p.evaluate("""(()=>{const U=window.SbxUI;const z=document.createElement('div');z.id='catalogue';z.style.cssText='position:fixed;inset:0;z-index:999;background:var(--sbx-fond);padding:16px;display:grid;grid-template-columns:repeat(3,1fr);gap:16px;overflow:auto';
      const corps=document.createElement('div');corps.appendChild(U.Tabs({onglets:[{id:'a',label:'Récents'},{id:'b',label:'Favoris'},{id:'c',label:'Système'}],actif:'a',onChange:id=>{window.__tab=id}}));
      const tiles=document.createElement('div');tiles.className='sbx-tiles';['Radio','WAF','DNS','Mail'].forEach((l,i)=>tiles.appendChild(U.Tile({icone:'module',label:l,onClick:()=>{},status:['active','idle','offline','stale'][i]})));corps.appendChild(tiles);
      const c=U.Card({id:'securite',icone:'bouclier',titre:'Sécurité',status:'active',source:'sbxwaf',corps:corps,action:{label:'Ouvrir Sécurité',href:'https://waf.sbx.test/',cible:'_blank'}});c.sbxReleve(new Date('2026-10-21T08:00:00'));z.appendChild(c);
      const c2=U.Card({id:'news',icone:'actualite',titre:'Actualités',status:'idle'});c2.corps.appendChild(U.NewsItem({titre:'Un titre d’actualité assez long pour être coupé sur deux lignes',source:'MetaNews',date:new Date(Date.now()-3600e3).toISOString(),href:'https://news.sbx.test/1',cible:'_blank',vignette:'/medaillons/01-communaute.webp'}));z.appendChild(c2);
      const c3=U.Card({id:'appareils',icone:'reseau',titre:'Appareils',status:'offline'});c3.corps.appendChild(U.DeviceRow({nom:'Imprimante',ip:'192.168.1.42',lien:'http://192.168.1.42/',vu:new Date(Date.now()-120e3).toISOString()}));c3.corps.appendChild(U.ModuleTile({id:'dns',icone:'globe',nom:'DNS',sousTitre:'ad-guard · 12 k requêtes',status:'active',onClick:()=>{}}));c3.sbxReleve(new Date(),true);z.appendChild(c3);
      document.body.appendChild(z);})()""")
    # Card : en-tête icône + titre + pastille + action ›, pied « Relevé HH:MM:SS »
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=securite] header svg.sbx-ico')") is not None
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=securite] .sbx-card-statut').textContent") == "actif"
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=securite] .sbx-card-action').getAttribute('aria-label')") == "Ouvrir Sécurité"
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=securite] .sbx-card-action').rel") == "noopener"
    assert p.inner_text("#catalogue .sbx-card[data-module=securite] .sbx-releve") == "Relevé 08:00:00"
    # statuts → pastille et opacité par CSS, « données périmées » force stale
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=news] .sbx-card-statut').textContent") == "en veille"
    assert p.evaluate("document.querySelector('#catalogue .sbx-card[data-module=appareils]').getAttribute('data-status')") == "stale"
    assert p.inner_text("#catalogue .sbx-card[data-module=appareils] .sbx-releve").startswith("données périmées")
    assert float(p.evaluate("getComputedStyle(document.querySelector('#catalogue .sbx-card[data-module=news]')).opacity")) < 1
    # Tabs : rôles et clavier
    assert p.evaluate("document.querySelector('#catalogue .sbx-tabs').getAttribute('role')") == "tablist"
    p.focus("#catalogue [role=tab][aria-selected=true]")
    p.keyboard.press("ArrowRight")
    assert p.evaluate("document.activeElement.getAttribute('data-id')") == "b" and p.evaluate("window.__tab") == "b"
    # Tiles : vrais boutons, grille auto-fill ≥ 104 px, led par statut
    assert p.evaluate("[...document.querySelectorAll('#catalogue .sbx-tile')].every(t=>t.tagName==='BUTTON' && t.getBoundingClientRect().width>=104)")
    assert p.evaluate("[...document.querySelectorAll('#catalogue .sbx-tile .sbx-led')].map(l=>l.getAttribute('data-ton'))") == ["ok", "info", "off", "warn"]
    # NewsItem, DeviceRow, ModuleTile
    assert p.evaluate("getComputedStyle(document.querySelector('#catalogue .sbx-news-vignette')).aspectRatio") in ("16 / 10", "1.6")
    assert "il y a 1 h" in p.inner_text("#catalogue .sbx-news-meta")
    assert p.inner_text("#catalogue .sbx-device .vu") == "il y a 2 min" and p.evaluate("document.querySelector('#catalogue .sbx-device a.ip').textContent") == "192.168.1.42"
    assert p.inner_text("#catalogue .sbx-mtile b") == "DNS"
    # aucun emoji rendu, pas de débordement
    assert not re.search(r"[\U0001F300-\U0001FAFF]", p.inner_text("#catalogue"))
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "hall-v2-catalogue.png"))
    assert erreurs == []
    ctx.close()


def test_hero_tablette_et_mobile_sans_debordement(nav):
    for largeur in (834, 390):
        ctx, p, erreurs = ouvre(nav, largeur)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), largeur
        assert p.evaluate("document.querySelector('.sbx-hero-salut').getBoundingClientRect().width") > largeur * 0.8
        if CAPTURES:
            p.screenshot(path=str(Path(CAPTURES) / f"hall-v2-{largeur}-hero.png"))
        assert erreurs == []
        ctx.close()

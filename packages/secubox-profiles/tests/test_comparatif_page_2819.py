# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2819 — /profiles/comparatif.html : les quatre profils (profil Aurora), le profil ACTIF de la box, les modules installes, ce que Minimal n'a pas.
Vrai navigateur, API simulee, et la VRAIE feuille hybrid-skin (sinon les fonds Aurora deviennent transparents sans que le test le voie)."""
import json
import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "profiles" / "comparatif.html"
SKIN = PKG.parent / "secubox-hub" / "www" / "shared" / "hybrid-skin.css"
playwright = pytest.importorskip("playwright.sync_api")


def fiche(paquets, espace="protection"):
    return [{"paquet": x, "espace": espace} for x in paquets]


MINI = ["secubox-dpi", "secubox-dns-guard", "secubox-ad-guard", "secubox-nac", "secubox-freebox"]
LITE = MINI + ["secubox-waf-ng", "secubox-wireguard"]
ISP = LITE + ["secubox-mail", "secubox-gitea"]
FULL = ISP + ["secubox-webos", "secubox-avatar"]
CONTENU = {"version": 1, "dpkg": "ok", "actif": "lite", "profils_installes": ["lite"], "installes": MINI + ["secubox-waf-ng"],
           "espaces": [{"id": "protection", "nom": "Protection", "icone": "🛡️", "ordre": 2}, {"id": "services", "nom": "Services", "icone": "📦", "ordre": 4}, {"id": "autres", "nom": "Autres", "icone": "", "ordre": 99}],
           "profils": [
               {"id": "minimal", "label": "Minimal", "meta": "secubox-minimal", "version": "0.1.0-1", "inclut": None, "directs": fiche(MINI), "modules": fiche(MINI), "ajoutes": fiche(MINI), "total": 5},
               {"id": "lite", "label": "Lite", "meta": "secubox-lite", "version": "1.8.0-1", "inclut": None, "directs": fiche(LITE), "modules": fiche(LITE), "ajoutes": fiche(LITE), "total": 7},
               {"id": "isp", "label": "ISP", "meta": "secubox-isp", "version": "1.4.0-1", "inclut": "lite", "directs": fiche(["secubox-mail", "secubox-gitea"], "services"), "modules": fiche(ISP), "ajoutes": fiche(["secubox-mail", "secubox-gitea"], "services"), "total": 9},
               {"id": "full", "label": "Full", "meta": "secubox-full", "version": "1.7.0-1", "inclut": "isp", "directs": fiche(["secubox-webos", "secubox-avatar"], "autres"), "modules": fiche(FULL), "ajoutes": fiche(["secubox-webos", "secubox-avatar"], "autres"), "total": 11}],
           "absents_de_minimal": fiche(["secubox-waf-ng", "secubox-wireguard"]) + fiche(["secubox-mail", "secubox-gitea"], "services") + fiche(["secubox-webos", "secubox-avatar"], "autres")}
STATUS = {"modules": [{"id": "dpi", "rss_kb": 80000}, {"id": "nac", "rss_kb": 20000}, {"id": "waf-ng", "rss_kb": 25000}, {"id": "mail", "rss_kb": None}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, contenu=CONTENU, statut_api=200, url="http://sbx.test/profiles/comparatif.html"):
    ctx = navigateur.new_context(viewport={"width": 1400, "height": 1000})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "shared/hybrid-skin.css":
            r.fulfill(status=200, content_type="text/css", body=SKIN.read_text(encoding="utf-8"))
        elif chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin == "profiles/comparatif.html":
            r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        u = r.request.url.split("/api/v1/profiles", 1)[1].split("?")[0]
        if statut_api != 200:
            return r.fulfill(status=statut_api, content_type="application/json", body='{"detail":"jeton requis"}')
        corps = {"/comparatif": contenu, "/status": STATUS}.get(u)
        r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps or {}))
    p.route("http://sbx.test/api/v1/profiles/**", api)
    p.goto(url)
    return ctx, p, erreurs


def test_les_quatre_profils_et_le_profil_actif(navigateur):
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    assert p.locator(".profil").count() == 4
    assert [t.strip().lower() for t in p.locator(".profil h3 b").all_inner_texts()] == ["minimal", "lite", "isp", "full"]
    assert "ACTIF" in p.inner_text(".profil[data-profil=lite] .badge") and p.locator(".profil[data-profil=minimal] .badge:not(.cible)").count() == 0
    assert "LITE" in p.inner_text("#etat").upper() and err == []
    ctx.close()


def test_chaque_carte_dit_ce_qu_elle_ajoute_et_ce_qu_elle_inclut(navigateur):
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    isp = p.locator(".profil[data-profil=isp]")
    assert "Lite" in isp.locator(".inclut").inner_text() and "+ 2" in isp.locator(".inclut").inner_text()
    assert "mail" in isp.inner_text() and "gitea" in isp.inner_text() and isp.locator(".chip", has_text="waf-ng").count() == 0     # le delta, pas le cumul
    assert "9" in isp.locator(".total").inner_text()
    ctx.close()


def test_les_modules_installes_sur_cette_box_sont_marques(navigateur):
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    lite = p.locator(".profil[data-profil=lite]")
    assert lite.locator(".chip.on", has_text="dpi").count() == 1 and lite.locator(".chip.on", has_text="wireguard").count() == 0
    assert "6 / 7" in p.inner_text("#tInst").replace("\n", " ") or "6/7" in p.inner_text("#tInst").replace(" ", "")
    ctx.close()


def test_la_memoire_est_celle_mesuree_pas_une_estimation(navigateur):
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    t = p.inner_text("#tMem")
    assert t.strip() == "122 Mo"                          # (80000 + 20000 + 25000) ko / 1024
    assert "3" in p.inner_text("#tMemS")                  # 3 modules mesures sur 7
    ctx.close()


def test_ce_que_minimal_n_a_pas_est_liste(navigateur):
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    zone = p.inner_text("#absents")
    for nom in ("waf-ng", "wireguard", "mail", "gitea", "webos", "avatar"):
        assert nom in zone, nom
    ctx.close()


def test_les_fonds_survivent_a_la_feuille_hybrid_skin(navigateur):
    """Piege : `body.hybrid-skin main * {background-color: transparent !important}` rend invisible tout fond pose en CSS."""
    ctx, p, err = ouvre(navigateur)
    p.wait_for_selector(".profil")
    p.evaluate("document.body.classList.add('hybrid-skin'); const l=document.createElement('link'); l.rel='stylesheet'; l.href='/shared/hybrid-skin.css'; document.head.appendChild(l)")
    p.wait_for_timeout(400)
    for sel in (".profil", ".chip.on", ".jauge i"):
        fond = p.evaluate("(s) => getComputedStyle(document.querySelector(s)).backgroundColor", sel)
        assert fond not in ("rgba(0, 0, 0, 0)", "transparent"), (sel, fond)
    ctx.close()


def test_session_requise_et_contenu_absent_sont_dits(navigateur):
    ctx, p, err = ouvre(navigateur, statut_api=401)
    p.wait_for_selector("#session:not([hidden])")
    assert "session" in p.inner_text("#session").lower()
    ctx.close()


def test_donnees_d_api_jamais_interpretees_en_html(navigateur):
    piege = json.loads(json.dumps(CONTENU))
    piege["profils"][1]["ajoutes"][0]["paquet"] = "secubox-<img src=x onerror=window.PWNED=1>"
    ctx, p, err = ouvre(navigateur, piege)
    p.wait_for_selector(".profil")
    assert "<img src=x" in p.inner_text(".profil[data-profil=lite]") and p.evaluate("window.PWNED === undefined")
    ctx.close()


def test_page_autonome_sans_dialogue_natif_ni_innerhtml():
    src = PAGE.read_text(encoding="utf-8")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src and re.findall(r'<script src="([^"]+)"', src) == ["/shared/sidebar.js"]
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "onclick="):
        assert interdit not in src, interdit
    assert "sbx_token" in src and "sbxVue" in src and "demo" in src


def test_la_page_est_installee_et_atteignable_depuis_profils_de_modules():
    assert "www/profiles/comparatif.html usr/share/secubox/www/profiles/" in (PKG / "debian" / "install").read_text()
    assert 'href="/profiles/comparatif.html"' in (PKG / "www" / "profiles" / "index.html").read_text(encoding="utf-8")

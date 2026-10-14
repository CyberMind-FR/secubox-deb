# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2687 — page PUBLIQUE du lecteur ytsas au profil Aurora : statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "ytsas" / "public.html"
SRC = PAGE.read_text(encoding="utf-8")
# les contrôles statiques portent sur le code, pas sur les commentaires qui expliquent les interdits
CODE = re.sub(r"<!--.*?-->", "", SRC, flags=re.S)


def test_page_autonome_sans_dialogue_natif_ni_innerhtml():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.search(r"<script[^>]+src=", CODE) and not re.search(r"<link[^>]+href=", CODE)   # ni sidebar, ni skin partagé
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "onclick=", "document.write"):
        assert interdit not in CODE
    assert "lorem" not in CODE.lower() and "demo" not in CODE.lower()


def test_memes_appels_et_rien_de_plus():
    for r in ("API + '/list'", "API + '/add'", "'/conserve/'", "'/stream/'"):
        assert r in CODE
    assert "var API = '/api/v1/ytsas'" in CODE
    assert "JSON.stringify({ url: val })" in CODE
    # page publique : ni jeton, ni stockage, ni action destructrice, ni dépôt de cookies
    for absent in ("sbx_token", "localStorage", "sessionStorage", "Authorization", "/remove", "/purge", "/cookies", "DELETE"):
        assert absent not in CODE, absent
    assert len(re.findall(r"method: '(?:POST|GET|PUT|DELETE)'", CODE)) == 2          # /conserve et /add, comme avant
    assert not re.search(r"credentials", CODE)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


LISTE = [
    {"id": "a1", "title": "Vidéo prête", "complete": True},
    {"id": "b2", "title": "Vidéo en cours", "progress": 0.4, "job_status": "running"},
    {"id": "c3", "title": "Miroir <b>x</b>", "complete": True, "peertube_url": "https://tube.example/videos/embed/zz"},
    {"id": "d4", "title": "Cassée", "job_status": "error"},
    {"id": "e5", "title": "Piégée", "complete": True, "peertube_url": "javascript:alert(1)"},
]


def ouvre(navigateur, liste=LISTE, extra=None, taille=None):
    extra = extra or {}
    ctx = navigateur.new_context(viewport=taille or {"width": 1000, "height": 800})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def route(r, *_):
        url = r.request.url.split("http://sbx.test", 1)[1]
        chemin = url.split("?")[0]
        if chemin == "/":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin.startswith("/api/v1/ytsas/stream/"):
            appels.append((r.request.method, chemin, None, dict(r.request.headers)))
            r.fulfill(status=200, content_type="video/mp4", body=b"")
        elif chemin.startswith("/api/"):
            appels.append((r.request.method, chemin, r.request.post_data, dict(r.request.headers)))
            statut, corps = extra.get((r.request.method, chemin), (200, liste) if chemin.endswith("/list") else (404, {"error": "absent"}))
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", route)
    p.goto("http://sbx.test/")
    return ctx, p, erreurs, appels


def test_liste_tuiles_et_pastilles(navigateur):
    ctx, p, err, appels = ouvre(navigateur)
    p.wait_for_selector(".ligne")
    assert p.locator(".ligne").count() == 5
    assert p.inner_text("#statPending") == "1" and p.inner_text("#statReady") == "3"       # l'erreur n'est comptée nulle part
    assert "40%" in p.inner_text(".ligne.cours") and p.locator(".ligne.erreur").count() == 1
    assert p.locator("#list b").count() == 0                                                # titre rendu en texte
    assert "Miroir <b>x</b>" in p.inner_text(".ligne.miroir")
    assert appels[0][0] == "GET" and appels[0][1] == "/api/v1/ytsas/list" and "authorization" not in appels[0][3]
    assert err == []
    ctx.close()


def test_ajout_envoie_le_meme_corps_sans_jeton(navigateur):
    extra = {("POST", "/api/v1/ytsas/add"): (200, {"id": "n9", "title": "Nouvelle"})}
    ctx, p, err, appels = ouvre(navigateur, extra=extra)
    p.wait_for_selector(".ligne")
    p.fill("#urlInput", " https://example.org/v?id=1 ")
    p.click("#btnAdd")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/api/v1/ytsas/add"][0]
    assert json.loads(post[2]) == {"url": "https://example.org/v?id=1"}
    assert post[3]["content-type"] == "application/json" and "authorization" not in post[3]
    assert p.input_value("#urlInput") == "" and err == []
    ctx.close()


def test_ajout_refuse_message_dans_la_page(navigateur):
    extra = {("POST", "/api/v1/ytsas/add"): (400, {"error": "lien non supporté"})}
    ctx, p, err, _ = ouvre(navigateur, extra=extra)
    p.wait_for_selector(".ligne")
    p.fill("#urlInput", "n'importe"); p.click("#btnAdd")
    p.wait_for_selector("#toast.erreur")
    assert "lien non supporté" in p.inner_text("#toast") and not p.is_disabled("#btnAdd") and err == []
    p.fill("#urlInput", ""); p.click("#btnAdd")
    assert "Lien requis" in p.inner_text("#toast")
    ctx.close()


def test_lire_ouvre_le_flux_et_conserver_poste_sans_corps(navigateur):
    extra = {("POST", "/api/v1/ytsas/conserve/a1"): (200, {"ok": True})}
    ctx, p, err, appels = ouvre(navigateur, extra=extra)
    p.wait_for_selector(".ligne")
    ligne = p.locator(".ligne[data-id='a1']")
    ligne.get_by_text("Lire").click()
    p.wait_for_selector(".ligne[data-id='a1'] video")
    assert p.get_attribute(".ligne[data-id='a1'] video", "src") == "/api/v1/ytsas/stream/a1"
    p.locator(".ligne[data-id='a1']").get_by_text("Fermer").click()
    p.wait_for_function("document.querySelectorAll('video').length === 0")
    p.locator(".ligne[data-id='a1']").get_by_text("Conserver").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('Conservation')")
    assert ("POST", "/api/v1/ytsas/conserve/a1", None) == appels_post(appels, "/api/v1/ytsas/conserve/a1")
    assert err == []
    ctx.close()


def appels_post(appels, chemin):
    a = [x for x in appels if x[0] == "POST" and x[1] == chemin][0]
    return (a[0], a[1], a[2])


def test_miroir_iframe_seulement_si_http_s(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector(".ligne")
    p.locator(".ligne[data-id='c3']").get_by_text("Lire").click()
    p.wait_for_selector(".ligne[data-id='c3'] iframe")
    assert p.get_attribute(".ligne[data-id='c3'] iframe", "src").startswith("https://tube.example/")
    p.locator(".ligne[data-id='e5']").get_by_text("Lire").click()
    assert p.locator(".ligne[data-id='e5'] iframe").count() == 0 and p.locator(".ligne[data-id='e5'] video").count() == 0
    assert err == []
    ctx.close()


def test_liste_vide_et_erreur_de_chargement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, liste=[])
    p.wait_for_function("document.getElementById('list').textContent.includes('Rien')")
    assert p.inner_text("#statPending") == "0"
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, extra={("GET", "/api/v1/ytsas/list"): (500, {})})
    p.wait_for_function("document.getElementById('list').textContent.includes('Erreur de chargement')")
    assert p.inner_text("#statPending") == "—" and p.inner_text("#statReady") == "—"
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    longue = [{"id": "z", "title": "T" * 300, "complete": True}] + LISTE
    ctx, p, err, _ = ouvre(navigateur, liste=longue, taille={"width": 420, "height": 800})
    p.wait_for_selector(".ligne")
    p.locator(".ligne[data-id='a1']").get_by_text("Lire").click()
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth") and err == []
    ctx.close()

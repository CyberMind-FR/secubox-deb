# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2538 — /health/ au profil Aurora : tuiles-filtres cliquables, lignes dépliables ET sélectionnables, WAF rejouable avec retour intégré. Vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www"
TYPES = {"html": "text/html", "js": "application/javascript", "css": "text/css"}
BATCH = {"modules": {
    "waf": {"status": "ok", "msg": "Running"}, "haproxy": {"status": "ok", "msg": "Running"}, "dns-guard": {"status": "ok", "msg": "Monté dans l'agrégateur"},
    "certs": {"status": "warn", "msg": "Active (auto-restart)"}, "mail": {"status": "error", "msg": "Failed"},
    "backup": {"status": "ok", "msg": "Au repos", "veille": True}, "nac": {"status": "ok", "msg": "Running"}, "torrent": {"status": "warn", "msg": "inactive/dead"}}, "count": 8}
MENU = {"espaces": [{"id": "protection", "nom": "Protection", "items": [{"id": "dns-guard", "name": "DNS Guard", "path": "/dns-guard/"}, {"id": "mail", "name": "Courrier", "path": "/mail/"}]}]}
DOCTOR = {"checks": {"waf-selftest": {"ok": True, "details": {"age_s": 12, "tests": [{"libelle": "Injection SQL", "attendu": "403", "code": 403, "ok": True}]}}}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        f = WWW / chemin
        f = f / "index.html" if f.is_dir() else f
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif f.is_file():
            r.fulfill(status=200, content_type=TYPES[f.suffix[1:]], body=f.read_text(encoding="utf-8"))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def repond(statut, corps):
        return lambda r, *_: r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    for chemin, (statut, corps) in routes.items():
        p.route("http://sbx.test" + chemin, repond(statut, corps))
    if jeton:
        p.add_init_script(f"try{{localStorage.setItem('sbx_token','{jeton}')}}catch(e){{}}")
    p.goto(url)
    return ctx, p, erreurs


API = {"/api/v1/hub/public/health-batch": (200, BATCH), "/api/v1/hub/public/menu": (200, MENU), "/api/v1/health-doctor/checks": (200, DOCTOR),
       "/api/v1/hub/public/info": (200, {"hostname": "gk2"})}


def test_tuiles_comptent_les_etats_et_le_bandeau_dit_le_pire(navigateur):
    ctx, p, err = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    assert [p.inner_text(i) for i in ("#nOk", "#nVeille", "#nAtt", "#nHors", "#nTot")] == ["4", "1", "2", "1", "8"]
    assert "1 EN PANNE" in p.inner_text("#etat") and "santé" in p.inner_text("#nScore") and err == []
    ctx.close()


def test_cliquer_une_tuile_filtre_et_recliquer_enleve_le_filtre(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.click("[data-f=hors]")
    assert p.get_attribute("[data-f=hors]", "aria-pressed") == "true"
    assert p.locator(".svc").count() >= 1 and "Courrier" in p.inner_text("#common") and "Running" not in p.inner_text("#common")
    assert "1 / 8" in p.inner_text("#nbr")
    p.click("[data-f=hors]")
    assert p.get_attribute("[data-f=tous]", "aria-pressed") == "true" and "8 / 8" in p.inner_text("#nbr")
    ctx.close()


def test_filtre_texte_et_aucun_resultat(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.fill("#filtre", "failed")
    assert "Courrier" in p.inner_text("#common") and "1 / 8" in p.inner_text("#nbr")
    p.fill("#filtre", "zzzz")
    assert "Aucun" in p.inner_text("#vital") and "Aucun" in p.inner_text("#common")
    ctx.close()


def test_une_ligne_se_deplie_au_clic_et_au_clavier_avec_lien_vers_la_page(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    ligne = p.locator('.svc[data-id="dns-guard"] .svc-tete')
    assert ligne.get_attribute("aria-expanded") == "false"
    ligne.click()
    assert ligne.get_attribute("aria-expanded") == "true" and p.is_visible('.svc[data-id="dns-guard"] .svc-detail')
    assert p.get_attribute('.svc[data-id="dns-guard"] a.btn', "href") == "/dns-guard/"
    ligne.focus(); p.keyboard.press("Enter")
    assert ligne.get_attribute("aria-expanded") == "false"
    ligne.focus(); p.keyboard.press("Space")
    assert ligne.get_attribute("aria-expanded") == "true"
    ctx.close()


def test_le_texte_d_une_ligne_reste_selectionnable_sans_la_deplier(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    assert p.evaluate("getComputedStyle(document.querySelector('.svc-nom')).userSelect") in ("text", "auto")
    zone = p.locator('.svc[data-id="mail"] .svc-msg')
    zone.scroll_into_view_if_needed()
    bb = zone.bounding_box()
    # Un glisser-déposer sur le texte : le navigateur émet quand même un `click` ; la ligne ne doit PAS se déplier.
    p.mouse.move(bb["x"] + 1, bb["y"] + bb["height"] / 2)
    p.mouse.down()
    p.mouse.move(bb["x"] + min(bb["width"] - 1, 40), bb["y"] + bb["height"] / 2, steps=8)
    p.mouse.up()
    assert p.evaluate("String(getSelection()).length") > 0
    assert p.get_attribute('.svc[data-id="mail"] .svc-tete', "aria-expanded") == "false"
    ctx.close()


def test_un_simple_clic_sans_selection_deplie(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.locator('.svc[data-id="mail"] .svc-tete').click()
    assert p.get_attribute('.svc[data-id="mail"] .svc-tete', "aria-expanded") == "true"
    ctx.close()


PRESSE_PAPIERS = "window.__copie = null; Object.defineProperty(navigator, 'clipboard', {value: {writeText: t => { window.__copie = t; return Promise.resolve(); }}});"


def test_copier_l_identifiant_met_dans_le_presse_papiers(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.evaluate(PRESSE_PAPIERS)                       # http://sbx.test n'est pas un contexte sécurisé : on remplace l'API (la vraie box sert en HTTPS)
    p.wait_for_selector("#vital .svc")
    p.locator('.svc[data-id="haproxy"] .svc-tete').click()
    p.locator('.svc[data-id="haproxy"] button', has_text="Copier").click()
    p.wait_for_function("window.__copie === 'haproxy'")
    assert "Copié" in p.inner_text("#toast")
    ctx.close()


def test_copie_impossible_dit_quoi_faire(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.locator('.svc[data-id="haproxy"] .svc-tete').click()
    p.locator('.svc[data-id="haproxy"] button', has_text="Copier").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('impossible')")
    assert "sélectionnez" in p.inner_text("#toast")
    ctx.close()


def test_tout_deplier_et_pause_de_l_actualisation(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.click("#deplier")
    assert p.locator(".svc-detail:visible").count() == 8 and "Tout replier" in p.inner_text("#deplier")
    p.click("#pause")
    assert p.get_attribute("#pause", "aria-pressed") == "true" and "Reprendre" in p.inner_text("#pause")
    ctx.close()


def test_le_filtre_et_les_lignes_depliees_survivent_a_l_actualisation(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    p.wait_for_selector("#vital .svc")
    p.fill("#filtre", "run")
    p.locator('.svc[data-id="haproxy"] .svc-tete').click()
    p.click("#rafraichir")
    p.wait_for_function("!document.getElementById('rafraichir').disabled")
    assert p.input_value("#filtre") == "run" and p.get_attribute('.svc[data-id="haproxy"] .svc-tete', "aria-expanded") == "true"
    ctx.close()


def test_waf_section_et_relecture_avec_retour_integre(navigateur):
    routes = {**API, "/api/v1/health-doctor/waf-selftest/run": (200, DOCTOR["checks"]["waf-selftest"])}
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", routes, jeton="jeton-test")
    p.wait_for_selector("#wafSection:not([hidden])")
    assert "Injection SQL" in p.inner_text("#waf") and "il y a 12 s" in p.inner_text("#wafAge")
    p.click("#wafRun")
    p.wait_for_function("document.getElementById('retour').textContent.includes('rejoué')")
    ctx.close()


def test_waf_sans_session_dit_de_se_connecter_sans_boite_native(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", API)
    boites = []
    p.on("dialog", lambda d: (boites.append(d.type), d.dismiss()))
    p.wait_for_selector("#wafSection:not([hidden])")
    p.click("#wafRun")
    p.wait_for_function("document.getElementById('retour').textContent.length > 0 && !document.getElementById('wafRun').disabled")
    assert "Session requise" in p.inner_text("#retour") and boites == []
    ctx.close()


def test_sonde_waf_illisible_masque_la_section(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", {**API, "/api/v1/health-doctor/checks": (404, {})})
    p.wait_for_selector("#vital .svc")
    assert not p.is_visible("#wafSection")
    ctx.close()


def test_releve_en_preparation_et_erreur_http_sont_dits(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", {"/api/v1/hub/public/health-batch": (200, {"modules": {}, "count": 0, "warming": True})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert "préparation" in p.inner_text("#erreur") and "HORS LIGNE" in p.inner_text("#etat")
    ctx.close()
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", {"/api/v1/hub/public/health-batch": (500, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert "HTTP 500" in p.inner_text("#erreur")
    ctx.close()


def test_noms_echappes_demo_embed_et_pas_de_debordement_a_400px(navigateur):
    batch = {"modules": {"<img src=x onerror=window.__xss=1>": {"status": "ok", "msg": "<b>x</b>"}}}
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/", {"/api/v1/hub/public/health-batch": (200, batch)})
    p.wait_for_selector("#common .svc")
    assert p.evaluate("window.__xss") is None and "<b>x</b>" in p.inner_text("#common")
    ctx.close()
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/health/?demo=1&embed=1", {}, {"width": 400, "height": 800})
    p.wait_for_selector("#vital .svc")
    assert p.is_visible("#demo") and p.evaluate("document.body.classList.contains('emb')") and p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()


def test_aucune_boite_native_ni_ressource_externe():
    src = (WWW / "health" / "index.html").read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S))
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])%s\(" % f, code), f
    assert "googleapis" not in src and "health.js" not in src and "health.css" not in src

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2538 — /espace/ au profil Aurora : onglets réactifs, état tiré de health-batch, filtres, clavier. Vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www"
TYPES = {"html": "text/html", "js": "application/javascript", "css": "text/css"}


def IT(i, nom, actif=True, objet="SERVICE"):
    return {"id": i, "name": nom, "icon": "🔹", "path": f"/{i}/", "active": actif, "objet": objet, "description": f"desc {nom}"}


MENU = {"espaces": [
    {"id": "apercu", "nom": "Vue d'ensemble", "icone": "🏠", "items": [IT("hub", "Hub")]},
    {"id": "protection", "nom": "Protection", "icone": "🛡️", "items": [
        IT("waf", "WAF"), IT("dns-guard", "DNS Guard", False), IT("vpn", "WireGuard"), IT("backup", "Sauvegarde"), IT("fw", "Pare-feu", False)]},
    {"id": "systeme", "nom": "Système", "icone": "⚙️", "items": [IT("system", "Système", None), IT("core", "Noyau", None)]}]}
# `active` du menu est FAUX pour dns-guard (module monté dans l'agrégateur) : health-batch dit la vérité.
SANTE = {"modules": {"waf": {"status": "ok", "msg": "Running"}, "dns-guard": {"status": "ok", "msg": "Monté dans l'agrégateur"},
                     "vpn": {"status": "warn", "msg": "inactive/dead"}, "backup": {"status": "ok", "msg": "Au repos", "veille": True}}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 800})
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
    def repond(statut, corps):          # fabrique : Playwright passe (route, requête) au gestionnaire
        return lambda r, *_: r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    for chemin, (statut, corps) in routes.items():
        p.route("http://sbx.test" + chemin, repond(statut, corps))
    p.goto(url)
    return ctx, p, erreurs


API = {"/api/v1/hub/public/menu": (200, MENU), "/api/v1/hub/public/health-batch": (200, SANTE)}


def test_les_onglets_listent_les_espaces_avec_leur_compte_et_le_courant_est_selectionne(navigateur):
    ctx, p, err = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#onglets .onglet")
    assert p.locator("#onglets [role=tab]").count() == 3
    sel = p.locator("#onglets [aria-selected=true]")
    assert sel.count() == 1 and "Protection" in sel.inner_text() and "5" in sel.inner_text()
    assert err == []
    ctx.close()


def test_cliquer_un_onglet_change_d_espace_et_l_adresse(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#services .carte")
    p.click("#onglet-systeme")
    p.wait_for_function("document.getElementById('titre').textContent.includes('Système')")
    assert p.url.endswith("#systeme") and "Noyau" in p.inner_text("#services") and "WAF" not in p.inner_text("#services")
    ctx.close()


def test_l_etat_vient_de_health_batch_pas_de_active_du_menu(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#services .carte")
    carte = lambda nom: p.locator("#services a.carte", has_text=nom).first
    assert "actif" in carte("DNS Guard").inner_text()            # menu : active=False ; sonde : ok → actif
    assert "dégradé" in carte("WireGuard").inner_text()
    assert "en veille" in carte("Sauvegarde").inner_text()
    assert "à l’arrêt" in carte("Pare-feu").inner_text()          # ni sonde, active=False → repli
    ctx.close()


def test_le_point_de_l_onglet_dit_le_pire_etat_de_l_espace(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#onglets .onglet")
    assert p.locator("#onglet-protection .pt.hors").count() == 1       # le pare-feu est à l'arrêt
    assert p.locator("#onglet-systeme .pt").first.get_attribute("class").strip() == "pt"       # aucune sonde : inconnu, pas « ok »
    ctx.close()


def test_filtre_texte_et_filtre_d_etat(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#services a.carte")
    p.fill("#filtre", "wire")
    assert p.locator("#services a.carte").count() == 1 and "1 / 5" in p.inner_text("#nb")
    p.fill("#filtre", "")
    p.click("[data-etat=hors]")
    assert p.locator("#services a.carte").count() == 1 and "Pare-feu" in p.inner_text("#services")
    assert p.get_attribute("[data-etat=hors]", "aria-pressed") == "true" and p.get_attribute("[data-etat=tous]", "aria-pressed") == "false"
    p.fill("#filtre", "zzz")
    assert "Aucun service" in p.inner_text("#services")
    ctx.close()


def test_navigation_au_clavier_entre_les_onglets(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#onglets .onglet")
    p.focus("#onglet-protection")
    p.keyboard.press("ArrowRight")
    p.wait_for_function("location.hash === '#systeme'")
    p.keyboard.press("Home")
    p.wait_for_function("location.hash === '#apercu'")
    p.keyboard.press("End")
    p.wait_for_function("location.hash === '#systeme'")
    ctx.close()


def test_sans_adresse_on_ouvre_protection_et_le_hash_inconnu_garde_les_onglets(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/", API)
    p.wait_for_selector("#services a.carte")
    assert "Protection" in p.inner_text("#titre")
    ctx.close()
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#nimporte", API)
    p.wait_for_selector("#erreur:not([hidden])")
    assert "espace inconnu" in p.inner_text("#erreur") and p.locator("#onglets [role=tab]").count() == 3
    ctx.close()


def test_menu_indisponible_dit_pourquoi_et_marque_hors_ligne(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", {"/api/v1/hub/public/menu": (503, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert "HTTP 503" in p.inner_text("#erreur") and "HORS LIGNE" in p.inner_text("#etat")
    ctx.close()


def test_sonde_absente_retombe_sur_le_menu_sans_casser(navigateur):
    ctx, p, err = ouvre(navigateur, "http://sbx.test/espace/#protection", {"/api/v1/hub/public/menu": (200, MENU), "/api/v1/hub/public/health-batch": (500, {})})
    p.wait_for_selector("#services a.carte")
    assert "actif" in p.locator("#services a.carte", has_text="WAF").inner_text() and err == []
    ctx.close()


def test_demo_et_embed_et_aucun_debordement_a_400px(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/?demo=1&embed=1#protection", {}, {"width": 400, "height": 800})
    p.wait_for_selector("#services a.carte")
    assert p.is_visible("#demo") and p.evaluate("document.body.classList.contains('emb')")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()


def test_noms_et_descriptions_sont_echappes(navigateur):
    menu = {"espaces": [{"id": "protection", "nom": "Protection", "icone": "", "items": [{**IT("x", "<img src=x onerror=window.__xss=1>"), "description": "<b>d</b>"}]}]}
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/espace/#protection", {"/api/v1/hub/public/menu": (200, menu), "/api/v1/hub/public/health-batch": (200, {})})
    p.wait_for_selector("#services a.carte")
    assert p.evaluate("window.__xss") is None and "<b>d</b>" in p.inner_text("#services")
    ctx.close()


def test_aucune_boite_native_ni_ressource_externe():
    src = (WWW / "espace" / "index.html").read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S))
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])%s\(" % f, code), f
    assert "apercu.css" not in src and "googleapis" not in src

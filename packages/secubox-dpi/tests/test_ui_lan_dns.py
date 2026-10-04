# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1960 : cartes « Destinations non classées » et « Appareils du LAN (vue DNS) » de la page du DPI, dans un vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "dpi" / "index.html"
PIEGE = "<img src=x onerror=window.__pwn=1>"
USAGE = {"usages": [], "unknown": [
    {"name": "7cd77.v.fwmrm.net", "flows": 3, "bytes": 5_000_000, "pct": 0.0,
     "etiquette": {"organisation": "FreeWheel", "type": "publicite", "categorie": "advertising", "source": "ad-guard"}},
    {"name": "82.67.100.75", "flows": 9, "bytes": 90_000_000, "pct": 0.0},
    {"name": "cloudreplay.ftven.fr", "flows": 2, "bytes": 2_000_000, "pct": 0.0, "etiquette": {"organisation": "France Télévisions", "type": "contenu", "categorie": "", "source": "ad-guard"}}],
    "adguard": {"etiquetes": 2, "total": 3}}
LAN = {"disponible": True, "age_s": 120, "fenetre": "jour courant (UTC)", "appareils": [
    {"nom": "TV fb5b", "mac": "38:07:16:94:fb:5b", "adresses": ["192.168.1.128", "2a01:e0a::7"], "mode": "auto", "origine": "auto", "requetes": 50, "bloquees": 10, "domaines": 3,
     "services": [{"organisation": "France Télévisions", "type": "contenu", "requetes": 40, "bloquees": 0}, {"organisation": "FreeWheel", "type": "publicite", "requetes": 10, "bloquees": 10}],
     "types": {"contenu": 40, "publicite": 10}}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, usage=USAGE, lan=LAN, usage_html=False):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        chemin = route.request.url.split("/api/v1/dpi", 1)[1].split("?")[0]
        if chemin == "/usage":
            if usage_html:
                return route.fulfill(status=502, content_type="text/html", body="<html>502</html>")
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(usage))
        if chemin == "/lan_dns":
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(lan))
        route.fulfill(status=200, content_type="application/json", body="{}")
    p.route("http://sbx.test/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))        # d'abord le fourre-tout : la DERNIÈRE règle posée gagne
    p.route("http://sbx.test/api/v1/dpi/**", api)
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    return ctx, p, erreurs


def mes_erreurs(erreurs):
    return [e for e in erreurs if "adg" in e.lower() or "Adg" in e]


def test_destinations_non_classees_etiquetees_d_abord_avec_la_source(navigateur):
    ctx, p, erreurs = _page(navigateur)
    p.wait_for_selector("#adg-unknown .app-item")
    lignes = p.locator("#adg-unknown .app-item")
    assert lignes.count() == 3
    assert "7cd77.v.fwmrm.net" in lignes.nth(0).inner_text() or "cloudreplay.ftven.fr" in lignes.nth(0).inner_text()      # les étiquetées d'abord
    assert "82.67.100.75" in lignes.nth(2).inner_text() and "non étiquetée" in lignes.nth(2).inner_text()
    fw = p.locator("#adg-unknown .app-item", has_text="7cd77.v.fwmrm.net").inner_text()
    assert "FreeWheel" in fw and "publicité" in fw and "d’après ad-guard" in fw
    pied = p.inner_text("#adg-unknown-foot")
    assert "3 destination(s) non classée(s)" in pied and "2 étiquetée(s)" in pied and "mesurés par le DPI" in pied
    assert "mesurés par le DPI" in p.inner_text("#adg-unknown-card h2") and not mes_erreurs(erreurs)
    ctx.close()


def test_appareils_du_lan_vus_au_dns_sans_aucun_volume(navigateur):
    ctx, p, erreurs = _page(navigateur)
    p.wait_for_selector("#adg-lan .app-item")
    t = p.inner_text("#adg-lan-card")
    assert "TV fb5b" in t and "192.168.1.128" in t and "auto" in t.lower() and "50 requêtes" in t and "10 bloquées (20 %)" in t and "3 noms" in t
    assert "France Télévisions (contenu) 40" in t and "FreeWheel (publicité) 10" in t
    assert "vu au dns" in p.inner_text("#adg-lan-badge").lower() and "aucun volume" in p.inner_text("#adg-lan-foot") and "2 min" in p.inner_text("#adg-lan-foot")
    assert not re.search(r"\d+(\.\d+)? ?(B|KB|MB|GB|TB)\b", t)                                    # le DNS ne donne pas de volumes : aucun n'est affiché
    assert not mes_erreurs(erreurs)
    ctx.close()


def test_texte_piege_inoffensif_dans_les_deux_cartes(navigateur):
    usage = {"unknown": [{"name": PIEGE, "bytes": 1, "etiquette": {"organisation": PIEGE, "type": PIEGE, "categorie": PIEGE, "source": "ad-guard"}}], "adguard": {"etiquetes": 1, "total": 1}}
    lan = {"disponible": True, "age_s": 1, "fenetre": PIEGE, "appareils": [{"nom": PIEGE, "adresses": [PIEGE], "mode": PIEGE, "requetes": 1, "bloquees": 0, "domaines": 1,
                                                                           "services": [{"organisation": PIEGE, "type": PIEGE, "requetes": 1, "bloquees": 0}], "types": {}}]}
    ctx, p, erreurs = _page(navigateur, usage, lan)
    p.wait_for_selector("#adg-lan .app-item")
    assert PIEGE in p.inner_text("#adg-unknown") and PIEGE in p.inner_text("#adg-lan")             # affiché en TEXTE
    assert p.evaluate("window.__pwn === undefined")
    assert p.evaluate("document.querySelectorAll('#adg-unknown-card img, #adg-lan-card img').length") == 0
    assert not mes_erreurs(erreurs)
    ctx.close()


def test_donnees_ad_guard_absentes_ou_perimees_message_explicite(navigateur):
    for lan, mot in (({"disponible": False, "raison": "périmé", "age_s": 5000}, "périmé"), ({"disponible": False, "raison": "absent"}, "absent"), ({}, "absentes")):
        ctx, p, erreurs = _page(navigateur, lan=lan)
        p.wait_for_selector("#adg-lan .empty")
        assert "absentes ou périmées" in p.inner_text("#adg-lan") and mot in p.inner_text("#adg-lan") and "indisponible" in p.inner_text("#adg-lan-badge").lower()
        assert not mes_erreurs(erreurs)
        ctx.close()


def test_api_usage_en_erreur_ne_leve_aucune_exception(navigateur):
    ctx, p, erreurs = _page(navigateur, usage_html=True)
    p.wait_for_selector("#adg-unknown .empty")
    assert "indisponibles" in p.inner_text("#adg-unknown") and not mes_erreurs(erreurs)
    ctx.close()


def test_sans_liste_non_classee_message_et_sessions_mentionne_la_mesure_du_dpi(navigateur):
    ctx, p, erreurs = _page(navigateur, usage={"usages": [], "unknown": []})
    p.wait_for_selector("#adg-unknown .empty")
    assert "Aucune destination non classée" in p.inner_text("#adg-unknown")
    assert "mesuré par le DPI" in p.locator(".card:has(#dpi-sessions) h2").inner_text()
    ctx.close()

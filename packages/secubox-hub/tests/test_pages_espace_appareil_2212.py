# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2212 : pages /espace/#<id> (services d'un espace) et /appareil/ (liste + fiche, source NAC) ; vrai navigateur, API simulée."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www"
TYPES = {"html": "text/html", "js": "application/javascript", "css": "text/css"}
IT = lambda i, nom, actif=True: {"id": i, "name": nom, "icon": "🔹", "path": f"/{i}/", "active": actif, "objet": "SERVICE", "description": "<b>desc</b>"}
MENU = {"espaces": [{"id": "protection", "nom": "Protection", "icone": "🛡️", "items": [IT("waf", "WAF"), IT("fw", "Pare-feu", False)]}]}
SANTE = {"modules": {"waf": {"status": "ok", "msg": "répond"}}}
CLIENTS = {"count": 2, "clients": [
    {"mac": "aa:bb:cc:00:00:01", "ip": "192.168.1.20", "hostname": "tv-salon", "custom_hostname": "", "online": True, "zone_name": "LAN", "device_type": "tv"},
    {"mac": "aa:bb:cc:00:00:02", "ip": "192.168.1.21", "hostname": "<img src=x onerror=window.__xss=1>", "online": False, "zone_name": "Quarantaine"}]}
FICHE = {**CLIENTS["clients"][0], "vendor": "Samsung", "first_seen": "2026-10-01", "recent_events": [{"timestamp": "2026-10-10T10:00", "event": "client_joined"}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes):
    ctx = navigateur.new_context()
    p = ctx.new_page()

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
    def repond(statut, corps):          # fabrique : Playwright passe (route, requête) à un gestionnaire à deux arguments
        return lambda r: r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    for chemin, (statut, corps) in routes.items():
        p.route("http://sbx.test" + chemin, repond(statut, corps))
    p.goto(url)
    return ctx, p


API = {"/api/v1/hub/public/menu": (200, MENU), "/api/v1/hub/public/health-batch": (200, SANTE)}


def test_page_espace_liste_les_services_avec_leur_etat(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/espace/#protection", API)
    p.wait_for_selector("#services .carte")
    t = p.inner_text("#services")
    assert "WAF" in t and "actif" in t and "Pare-feu" in t and "à l’arrêt" in t and "répond" in t
    assert "<b>desc</b>" in t and "Protection" in p.inner_text("#titre")
    ctx.close()


def test_page_espace_inconnu_dit_pourquoi(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/espace/#nimporte", API)
    p.wait_for_selector("#erreur:not([hidden])")
    assert "espace inconnu" in p.inner_text("#erreur")
    ctx.close()


def test_liste_appareils_echappe_les_noms_et_ouvre_la_fiche(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/", {"/api/v1/nac/clients": (200, CLIENTS), "/api/v1/nac/client/**": (200, FICHE)})
    p.wait_for_selector("#appareils .carte", state="attached")
    t = p.locator("#appareils").text_content()
    assert "tv-salon" in t and "hors ligne" in t
    assert p.evaluate("window.__xss") is None and "<img" in t
    p.click("#appareils summary")                               # le groupe « Non identifiés » est replié
    p.click("text=tv-salon")
    p.wait_for_selector("#fiche:not([hidden])")
    p.wait_for_selector("#detail .carte")
    t = p.inner_text("#detail")
    assert "Samsung" in t and "192.168.1.20" in t and "client_joined" in p.inner_text("#events")
    ctx.close()


def test_appareils_refus_api_affiche_une_erreur(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/", {"/api/v1/nac/clients": (401, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert "HTTP 401" in p.inner_text("#erreur")
    ctx.close()


FLUX = {"heures": 6, "domaines": [{"domaine": "ads.tracker.example", "service": "Régie", "type": "pub", "requetes": 14, "bloquees": 14},
                                  {"domaine": "<img src=x onerror=window.__xss=1>", "service": None, "type": None, "requetes": 3, "bloquees": 0}],
        "services": [{"service": "Netflix", "type": "video", "requetes": 120, "bloquees": 0, "domaines": 4}, {"service": "Régie", "type": "pub", "requetes": 14, "bloquees": 14, "domaines": 1}],
        "limite": "pas de volumes (octets) : le DNS ne les voit pas"}


def test_fiche_appareil_deduit_les_flux_du_dns_sans_dpi(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/#aa%3Abb%3Acc%3A00%3A00%3A01",
                   {"/api/v1/nac/client/**": (200, FICHE), "/api/v1/ad-guard/adblock-tv/flux**": (200, FLUX)})
    p.wait_for_selector("#flux .carte")
    t = p.inner_text("#flux")
    assert "Netflix" in t and "120" in t and "Régie" in t and "ads.tracker.example" in t
    assert "pas de volumes" in p.inner_text("#flux-limite")
    assert p.evaluate("window.__xss") is None
    ctx.close()


def test_flux_dns_indisponibles_ne_cassent_pas_la_fiche(navigateur):
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/#aa%3Abb%3Acc%3A00%3A00%3A01",
                   {"/api/v1/nac/client/**": (200, FICHE), "/api/v1/ad-guard/adblock-tv/flux**": (503, {})})
    p.wait_for_selector("#detail .carte")
    p.wait_for_function("document.getElementById('flux-limite').textContent.length > 0")
    assert "indisponible" in p.inner_text("#flux-limite") and p.locator("#erreur:not([hidden])").count() == 0
    ctx.close()


def test_les_conteneurs_lxc_ne_sont_pas_des_appareils(navigateur):
    clients = {"count": 4, "clients": [
        CLIENTS["clients"][0],
        {"mac": "3e:56:63:13:4e:8a", "ip": "10.100.0.10", "hostname": "mail", "online": True},            # pont br-lxc
        {"mac": "00:16:3e:1c:41:60", "ip": "fe80::216:3eff:fe1c:4160", "hostname": "nextcloud", "online": True},   # OUI LXC
        {"mac": "02:fb:00:00:d2:80", "ip": "10.55.0.2", "hostname": "tunnel", "online": True}]}
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/", {"/api/v1/nac/clients": (200, clients)})
    p.wait_for_selector("#appareils .carte", state="attached")
    assert p.locator("#appareils .carte").count() == 2          # tv-salon et le client 10.55.0.2 : seuls les conteneurs sont écartés
    t = p.locator("#appareils").text_content()
    assert "tv-salon" in t and "mail" not in t and "nextcloud" not in t
    assert "2 conteneurs lxc masqués" in p.inner_text("#liste").lower()
    ctx.close()


def test_les_appareils_sont_regroupes_par_mac_puis_par_type_avec_le_materiel(navigateur):
    clients = {"count": 5, "clients": [
        {"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.20", "hostname": "tv-salon", "online": True, "device_type": "smart_home", "oui_vendor": "Samsung Electronics", "model": "QN90"},
        {"mac": "aa:bb:cc:00:00:01", "ip": "2a01:e0a::20", "hostname": "tv-salon", "online": True, "device_type": "smart_home", "oui_vendor": "Samsung Electronics"},   # même MAC, autre adresse
        {"mac": "aa:bb:cc:00:00:03", "ip": "192.168.1.254", "hostname": "freebox", "online": True, "device_type": "router", "oui_vendor": "FREEBOX SAS", "is_router": 1},
        {"mac": "aa:bb:cc:00:00:04", "ip": "192.168.1.30", "online": False, "device_type": "unknown", "oui_vendor": "Unknown"},
        {"mac": "aa:bb:cc:00:00:05", "ip": "192.168.1.31", "online": False, "device_type": "unknown", "oui_vendor": "Unknown"}]}
    ctx, p = ouvre(navigateur, "http://sbx.test/appareil/", {"/api/v1/nac/clients": (200, clients)})
    p.wait_for_selector("#appareils .groupe")
    titres = [t.strip().lower() for t in p.locator("#appareils .groupe > summary").all_inner_texts()]
    assert titres[0].startswith("routeurs") and any(t.startswith("objets connectés") for t in titres)
    assert titres[-1].startswith("non identifiés") and "(2)" in titres[-1]            # inconnus en dernier, repliés
    assert p.locator("#appareils .carte:has-text('tv-salon')").count() == 1            # une carte par MAC
    carte = p.inner_text("#appareils .carte:has-text('tv-salon')")
    assert "Samsung Electronics" in carte and "QN90" in carte and "192.168.1.20" in carte and "2a01:e0a::20" in carte
    assert "Unknown" not in p.locator("#appareils").text_content()                                  # le fabricant « Unknown » n'est pas un matériel
    ctx.close()

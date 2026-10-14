# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2711 — l'IP de sortie Tor porte son pays : drapeau GeoIP, nom et ASN (route /admin/tor/state, sonde SOCKS, page /toolbox/tor.html)."""
import asyncio
import json
from pathlib import Path

import pytest

import secubox_toolbox.api as api

WWW = Path(__file__).resolve().parents[1] / "www" / "toolbox"
SRC = (WWW / "tor.html").read_text(encoding="utf-8")
GEO_DE = {"country_iso": "DE", "country_name": "Germany", "flag": "🇩🇪", "asn": 24940, "asn_org": "Hetzner Online GmbH"}


# ---------- API ----------

def test_geo_sortie_rend_pays_drapeau_et_asn(monkeypatch):
    monkeypatch.setattr("secubox_toolbox.geo.lookup", lambda k: dict(GEO_DE))
    assert asyncio.run(api._geo_sortie("185.220.101.45")) == GEO_DE


@pytest.mark.parametrize("ip", [None, "", "unknown", "pas une ip", "1.2.3", "999.1.1.1", "<script>"])
def test_geo_sortie_ignore_ce_qui_n_est_pas_une_adresse_sans_interroger_geoip(monkeypatch, ip):
    def boom(k):
        raise AssertionError("geo.lookup ne doit pas être appelé pour " + repr(k))
    monkeypatch.setattr("secubox_toolbox.geo.lookup", boom)
    assert asyncio.run(api._geo_sortie(ip)) == {}


def test_geo_sortie_ne_leve_jamais(monkeypatch):
    def casse(k):
        raise RuntimeError("base illisible")
    monkeypatch.setattr("secubox_toolbox.geo.lookup", casse)
    assert asyncio.run(api._geo_sortie("185.220.101.45")) == {}


def test_geo_sortie_n_expose_que_les_champs_attendus(monkeypatch):
    monkeypatch.setattr("secubox_toolbox.geo.lookup", lambda k: dict(GEO_DE, secret="x", chemin="/var/lib/GeoIP"))
    assert set(asyncio.run(api._geo_sortie("185.220.101.45"))) == {"country_iso", "country_name", "flag", "asn", "asn_org"}


def test_etat_tor_porte_le_pays_de_l_ip_de_sortie(monkeypatch):
    monkeypatch.setattr("secubox_toolbox.filters.get_filters", lambda force=False: {})
    monkeypatch.setattr("secubox_toolbox.tor_ctl.status", lambda: {"running": True, "bootstrap": 100})
    monkeypatch.setattr(api, "_tor_exit_ip_cached", lambda: "185.220.101.45")
    monkeypatch.setattr("secubox_toolbox.geo.lookup", lambda k: dict(GEO_DE))
    st = asyncio.run(api.admin_tor_state())
    assert st["exit_ip"] == "185.220.101.45" and st["exit_geo"]["country_iso"] == "DE" and st["exit_geo"]["flag"] == "🇩🇪"


def test_etat_tor_sans_ip_de_sortie_n_a_pas_de_pays(monkeypatch):
    monkeypatch.setattr("secubox_toolbox.filters.get_filters", lambda force=False: {})
    monkeypatch.setattr("secubox_toolbox.tor_ctl.status", lambda: {"running": False})
    monkeypatch.setattr(api, "_tor_exit_ip_cached", lambda: None)
    st = asyncio.run(api.admin_tor_state())
    assert st["exit_ip"] is None and st["exit_geo"] == {}


def test_la_sonde_socks_rend_aussi_le_pays(monkeypatch):
    class Rep:
        text = "204.8.96.89\n"

    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return Rep()
    monkeypatch.setattr("httpx.AsyncClient", Client)
    monkeypatch.setattr(api, "_require_tor_admin", lambda request: None)
    monkeypatch.setattr("secubox_toolbox.tor_ctl.tor_running", lambda: True)
    monkeypatch.setattr(api, "_TOR_EXIT_IP_CACHE", "/nonexistent-dir/tor_exit_ip")
    monkeypatch.setattr("secubox_toolbox.geo.lookup", lambda k: dict(GEO_DE, country_iso="US", flag="🇺🇸", country_name="United States"))
    r = asyncio.run(api.admin_tor_check_leaks(object()))
    assert r["ok"] is True and r["tor_ip"] == "204.8.96.89" and r["geo"]["country_iso"] == "US"


def test_la_sonde_en_echec_n_a_pas_de_pays(monkeypatch):
    class Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            raise OSError("socks injoignable")
    monkeypatch.setattr("httpx.AsyncClient", Client)
    monkeypatch.setattr(api, "_require_tor_admin", lambda request: None)
    monkeypatch.setattr("secubox_toolbox.tor_ctl.tor_running", lambda: True)
    r = asyncio.run(api.admin_tor_check_leaks(object()))
    assert r["ok"] is False and r["tor_ip"] is None and r.get("geo", {}) == {}


# ---------- page ----------

def test_la_page_lit_le_pays_et_n_affiche_plus_un_tiret_fixe():
    assert "exit_geo" in SRC and "L.geo" in SRC
    assert "Pays de sortie</span><span class=\"v\">—</span>" not in SRC      # l'ancienne ligne figée
    assert "innerHTML" in SRC and "esc(" in SRC                              # les valeurs reçues passent par esc()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, etat, sonde=None, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "toolbox/tor.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    # la dernière route déclarée l'emporte : le générique d'abord, le précis ensuite
    p.route("http://sbx.test/api/v1/**", lambda r, *_: r.fulfill(status=200, content_type="application/json", body="{}"))

    def api_toolbox(r, *_):
        chemin = r.request.url.split("/api/v1/toolbox", 1)[1].split("?")[0]
        if chemin == "/admin/tor/state":
            r.fulfill(status=200, content_type="application/json", body=json.dumps(etat))
        elif chemin == "/admin/tor/check-leaks" and sonde is not None:
            r.fulfill(status=200, content_type="application/json", body=json.dumps(sonde))
        else:
            r.fulfill(status=200, content_type="application/json", body="{}")
    p.route("http://sbx.test/api/v1/toolbox/**", api_toolbox)
    p.goto("http://sbx.test/toolbox/tor.html?embed=1")
    return ctx, p, erreurs


ETAT = {"running": True, "bootstrap": 100, "circuits": 3, "tor_mode": True, "exit_ip": "185.220.101.45", "exit_geo": GEO_DE}


def test_la_ligne_pays_de_sortie_montre_le_drapeau_le_nom_en_francais_et_l_asn(navigateur):
    ctx, p, err = ouvre(navigateur, ETAT)
    p.wait_for_function("document.getElementById('fuite').textContent.indexOf('Allemagne') >= 0")
    texte = p.inner_text("#fuite")
    assert "🇩🇪" in texte and "Allemagne" in texte and "DE" in texte and "AS24940" in texte and "Hetzner Online GmbH" in texte
    assert "Pays de sortie" in texte and err == []
    ctx.close()


def test_le_drapeau_est_aussi_dans_la_ligne_ip_de_sortie_de_l_etat(navigateur):
    ctx, p, err = ouvre(navigateur, ETAT)
    p.wait_for_function("document.getElementById('etat').textContent.indexOf('185.220.101.45') >= 0")
    assert "🇩🇪" in p.inner_text("#etat") and err == []
    ctx.close()


def test_pays_inconnu_de_la_liste_francaise_retombe_sur_le_nom_de_l_api(navigateur):
    geo = {"country_iso": "AQ", "country_name": "Antarctica", "flag": "🇦🇶", "asn": 0, "asn_org": ""}
    ctx, p, err = ouvre(navigateur, dict(ETAT, exit_geo=geo))
    p.wait_for_function("document.getElementById('fuite').textContent.indexOf('Antarctica') >= 0")
    texte = p.inner_text("#fuite")
    assert "🇦🇶" in texte and "AS0" not in texte and err == []        # un ASN inconnu n'est pas affiché
    ctx.close()


def test_sans_pays_la_ligne_reste_un_tiret_et_rien_n_est_invente(navigateur):
    ctx, p, err = ouvre(navigateur, dict(ETAT, exit_geo={}))
    p.wait_for_function("document.getElementById('fuite').textContent.indexOf('185.220.101.45') >= 0")
    texte = p.inner_text("#fuite")
    ligne = [ligne for ligne in texte.splitlines() if "Pays de sortie" in ligne or ligne.strip() == "—"]
    assert ligne and "🇩🇪" not in texte and err == []
    ctx.close()


def test_une_valeur_hostile_du_pays_reste_du_texte(navigateur):
    geo = {"country_iso": "DE", "country_name": "<img src=x onerror=alert(1)>", "flag": "🇩🇪", "asn": 1, "asn_org": "<b>x</b>"}
    ctx, p, err = ouvre(navigateur, dict(ETAT, exit_geo=geo))
    p.wait_for_function("document.getElementById('fuite').textContent.indexOf('185.220.101.45') >= 0")
    assert p.locator("#fuite img, #fuite b").count() == 0 and err == []
    ctx.close()


def test_a_420_px_la_ligne_ne_deborde_pas(navigateur):
    ctx, p, err = ouvre(navigateur, ETAT, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('fuite').textContent.indexOf('Allemagne') >= 0")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /mesh/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "mesh" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-light" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'mesh'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_identiques_a_l_ancienne_page():
    for r in ("/mesh/rf", "/mesh/peers", "/ap/clients", "/health", "/mesh/key/rotate", "'POST'"):
        assert r in SRC
    assert len(re.findall(r"ecrire\('(?:POST|DELETE|PUT)'", SRC)) == 1   # une seule écriture, comme avant


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


RF = {"iface": "wlan0", "type": "mesh point", "channel": 6, "freq_mhz": 2437, "txpower_dbm": 20.0, "width_mhz": 20, "reg_country": "FR", "reg_dfs_state": None}
PEERS = [{"mac": "02:00:00:00:00:01", "mesh_plink": "ESTAB", "signal_dbm": -58, "tx_bitrate_mbps": 72.2, "inactive_ms": 120, "rx_bytes": 2048, "tx_bytes": None},
         {"mac": "<b>x</b>", "mesh_plink": "OPN_SNT", "signal_dbm": None, "tx_bitrate_mbps": None, "inactive_ms": None, "rx_bytes": None, "tx_bytes": None}]
CLIENTS = [{"mac": "02:00:00:00:00:a1", "signal_dbm": -49, "connected_time_s": 5230, "passpoint": True, "rx_bytes": 10, "tx_bytes": 20}]
API = {"/mesh/rf": (200, RF), "/mesh/peers": (200, PEERS), "/ap/clients": (200, CLIENTS), "/health": (200, {"status": "ok", "module": "mesh", "version": "2.0.0"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "mesh":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/mesh", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/mesh/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mesh/", API)
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tPairs", "#tEstab", "#tClients", "#tCanal", "#tTx")] == ["2", "1", "1", "6", "20"]
    assert p.inner_text("#etat") == "EN LIGNE" and p.inner_text("#kFreq") == "2437 MHz" and p.inner_text("#kDfs") == "—"
    t = p.inner_text("#bPairs")
    assert "-58 dBm" in t and "72.2 Mb/s" in t and "120 ms" in t and "2.0 Ko" in t
    assert "<b>x</b>" in t and p.locator("#bPairs b").count() == 0     # texte, jamais du HTML
    assert "OUI" in p.inner_text("#bClients") and "87 min" in p.inner_text("#bClients")
    assert err == []
    ctx.close()


def test_rotation_confirmation_dans_la_page_et_meme_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mesh/", {**API, "/mesh/key/rotate": (200, {"status": "ok", "stdout": "OK", "stderr": ""})})
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    p.click("#rotation")
    assert p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    p.click("#confirmer")
    p.wait_for_function("document.getElementById('rRot').textContent.includes('demandée')")
    post = [a for a in appels if a[0] == "POST"]
    assert post and post[0][1] == "/mesh/key/rotate" and not post[0][2]
    assert err == []
    ctx.close()


def test_rotation_en_echec_http_200_est_signalee(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/mesh/", {**API, "/mesh/key/rotate": (200, {"status": "error", "reason": "wpa_cli not installed"})})
    p.click("#rotation"); p.click("#confirmer")
    p.wait_for_function("document.getElementById('rRot').textContent.includes('échec')")
    assert "ko" in p.get_attribute("#rRot", "class") and "wpa_cli" in p.inner_text("#rRot")
    ctx.close()


def test_annuler_n_ecrit_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/mesh/", API)
    p.click("#rotation"); p.click("#annuler")
    assert not p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_jeton_envoye(navigateur):
    ctx2, p, _, appels = ouvre(navigateur, "http://sbx.test/mesh/", API)
    p.evaluate("localStorage.setItem('sbx_token','abc')")
    p.click("#rafraichir"); p.wait_for_timeout(400)
    assert any(a[3] == "Bearer abc" for a in appels)
    ctx2.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mesh/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tPairs", "#tEstab", "#tClients", "#tCanal", "#tTx")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_action_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mesh/?demo=1", {})
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#rotation"); p.click("#confirmer")
    p.wait_for_function("document.getElementById('rRot').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mesh/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

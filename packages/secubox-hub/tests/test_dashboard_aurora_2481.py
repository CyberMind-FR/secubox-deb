# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2481 — Dashboard (racine de l'administration) au profil Aurora : lecture seule, session requise dite, tirets sans mesure, valeurs en texte brut."""
import concurrent.futures
import json
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "index.html"


def _nav(scenario, query="?demo=1", api=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [])
            pg = nav.new_page()
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            if api is not None:
                pg.route("http://t.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")) if r.request.url.endswith("/page") else api(r))
                pg.goto("http://t.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(600)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_aucune_boite_native_aucune_ecriture_aucun_alert():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    ecritures = re.findall(r"method:\s*'(POST|PUT|DELETE)'", src)
    assert ecritures == ["POST"]                                     # un seul POST : la fin de session, jamais une action sur la box
    assert "/api/v1/auth/auth/logout" in src and "execute_action" not in src and "network_mode', 'POST'" not in src


def test_demo_tuiles_ressources_sante_alertes_et_pied():
    def sc(pg):
        return ([pg.inner_text(i) for i in ("#tMod", "#tSante", "#tAl", "#tIf", "#tUp")], pg.locator("#res .barre-l").count(), pg.inner_text("#res .barre-l:nth-child(2) b"),
                pg.inner_text("#sMod .legs"), pg.inner_text("#sSites .legs"), pg.locator("#alertes .alerte").count(), pg.inner_text("#pVer"), pg.inner_text("#pastille"),
                pg.evaluate("document.getElementById('alertes').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#alertes img").count(), pg.is_visible("#demo"))
    (t, nb, mem, mods, sites, nal, ver, pastille, texte, imgs, demo), erreurs, natifs = _nav(sc)
    assert t[0].replace(" ", " ").replace("\xa0", " ") == "108 / 112" and t[1] == "91 %" and t[2] == "2" and t[3] == "5 / 6" and t[4] == "12d 4h 31m"
    assert nb == 3 and mem.startswith("62 %") and "Go" in mem and "en service : 105" in mods and "répondent : 30" in sites and nal == 2 and ver == "v3.0.0"
    assert pastille == "SANTÉ 91 % · TOUT VA BIEN" and texte and imgs == 0 and demo and erreurs == [] and natifs == []


def test_sans_aucune_mesure_les_tuiles_sont_des_tirets():
    def api(r):
        r.fulfill(status=500, body="{}")

    def sc(pg):
        return [pg.inner_text(i) for i in ("#tMod", "#tSante", "#tAl", "#tIf", "#tUp")], pg.inner_text("#pastille"), pg.is_visible("#session")
    (t, pastille, session), erreurs, _ = _nav(sc, api=api)
    assert t == ["—"] * 5 and pastille == "HORS LIGNE" and not session and erreurs == []


def test_session_requise_est_dite_avec_un_lien_de_connexion():
    def api(r):
        r.fulfill(status=401, body="{}")

    def sc(pg):
        return pg.inner_text("#pastille"), pg.is_visible("#session"), pg.get_attribute("#session a", "href"), pg.inner_text("#alertes")
    (pastille, session, lien, al), erreurs, _ = _nav(sc, api=api)
    assert pastille == "SESSION REQUISE" and session and lien == "/login.html" and "Session requise" in al and erreurs == []


def test_les_appels_portent_le_jeton_quand_il_existe_et_le_cookie_sinon():
    vus = []

    def api(r):
        vus.append((r.request.url.split("/api/v1/hub")[-1], r.request.headers.get("authorization")))
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"overall": 80}) if r.request.url.endswith("/system_health") else "null")

    def sc(pg):
        pg.evaluate("localStorage.setItem('sbx_token', 'jeton-exemple')")
        pg.click("#btn-refresh"); pg.wait_for_timeout(500)
        return pg.inner_text("#tSante")
    sante, erreurs, _ = _nav(sc, api=api)
    assert sante == "80 %" and erreurs == []
    assert any(a is None for _, a in vus) and any(a == "Bearer jeton-exemple" for _, a in vus)       # sans jeton : appel quand même (cookie) ; avec : en-tête


def test_aucune_alerte_est_dite_comme_telle():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body="[]" if r.request.url.endswith("/alerts") else "null")

    def sc(pg):
        return pg.inner_text("#tAl"), pg.inner_text("#alertes")
    (n, texte), erreurs, _ = _nav(sc, api=api)
    assert n == "0" and "Aucune alerte" in texte and erreurs == []

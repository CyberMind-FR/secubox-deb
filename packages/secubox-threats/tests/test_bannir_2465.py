# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2465 — /threats/ : bannir 30 jours une adresse PUBLIQUE, confirmation intégrée, erreurs réelles rendues, rien pour les adresses privées."""
import concurrent.futures
import json
import pathlib

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "threats" / "index.html"


def _nav(scenario, query="?demo=1", api=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [], [])
            pg = nav.new_page()
            erreurs, natifs, posts = [], [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            if api is not None:
                def route(r):
                    u = r.request.url
                    if u.endswith("/page"):
                        return r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
                    if r.request.method == "POST":
                        posts.append((u, r.request.post_data))
                        return api(r)
                    if "/alerts?" in u:
                        return r.fulfill(status=200, content_type="application/json", body=json.dumps({"total": 2, "alerts": [
                            {"timestamp": "2026-10-12T10:00:00Z", "source": "waf", "severity": "high", "message": "scan", "value": "185.220.101.3"},
                            {"timestamp": "2026-10-12T10:01:00Z", "source": "waf", "severity": "low", "message": "lan", "value": "192.168.1.50"}]}))
                    return r.fulfill(status=404, body="{}")
                pg.route("http://t.test/**", route)
                pg.goto("http://t.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(500)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs, posts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3], res[4]


def test_bouton_seulement_pour_les_adresses_publiques():
    def sc(pg):
        return pg.evaluate("[...document.querySelectorAll('#alertes tr')].map(r => [r.cells[4] && r.cells[4].textContent, !!r.querySelector('.ban')])")
    lignes, erreurs, natifs, _ = _nav(sc)
    par_ip = {ip: bouton for ip, bouton in lignes}
    assert par_ip["57.141.0.17"] is True and par_ip["185.220.101.3"] is True       # publiques
    assert par_ip["192.168.33.12"] is False and par_ip["10.0.0.42"] is False       # privées : jamais proposées
    assert erreurs == [] and natifs == []


def test_annuler_ne_bannit_rien_et_confirmer_en_demo_reste_inerte():
    def sc(pg):
        pg.click("#alertes .ban >> nth=0"); pg.wait_for_selector("#dialogue:not([hidden])")
        texte = pg.inner_text("#dialogue")
        pg.click("#dialogue .non"); pg.wait_for_selector("#dialogue[hidden]", state="attached")
        apres_annulation = pg.inner_text("#retour")
        pg.click("#alertes .ban >> nth=0"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue button:not(.non)")
        pg.wait_for_function("document.getElementById('retour').textContent.includes('Démonstration')")
        return texte, apres_annulation, pg.inner_text("#retour")
    (texte, annule, demo), erreurs, natifs, _ = _nav(sc)
    assert "30 jours" in texte and annule == "" and "aucun bannissement réel" in demo and erreurs == [] and natifs == []


def test_ban_reel_envoie_30d_et_affiche_le_succes():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"success": True, "ip": "185.220.101.3", "duration": "30d"}))

    def sc(pg):
        pg.wait_for_selector("#alertes .ban")
        n = pg.locator("#alertes .ban").count()
        pg.click("#alertes .ban"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue button:not(.non)")
        pg.wait_for_function("document.getElementById('retour').textContent.includes('banni')")
        return n, pg.inner_text("#retour"), pg.inner_text("#alertes .ban")
    (n, retour, bouton), erreurs, natifs, posts = _nav(sc, api=api)
    assert n == 1                                                                   # l'adresse 192.168.1.50 n'a pas de bouton
    assert len(posts) == 1 and posts[0][0].endswith("/api/v1/waf/ban")
    corps = json.loads(posts[0][1])
    assert corps["ip"] == "185.220.101.3" and corps["duration"] == "30d" and "Menaces" in corps["reason"]
    assert "185.220.101.3 est banni 30 jours" in retour and bouton == "Banni" and erreurs == [] and natifs == []


def test_refus_du_serveur_est_dit_et_le_bouton_reste_utilisable():
    def api(r):
        r.fulfill(status=500, content_type="application/json", body=json.dumps({"detail": "bannissement refusé : Adresse privée refusée"}))

    def sc(pg):
        pg.wait_for_selector("#alertes .ban"); pg.click("#alertes .ban"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue button:not(.non)")
        pg.wait_for_function("document.getElementById('retour').textContent.includes('refusé')")
        return pg.inner_text("#retour"), pg.is_enabled("#alertes .ban")
    (retour, actif), erreurs, _, _ = _nav(sc, api=api)
    assert retour.startswith("❌") and "Adresse privée refusée" in retour and actif and erreurs == []


def test_session_requise_et_message_hostile_sans_balise():
    def api(r):
        r.fulfill(status=401, content_type="application/json", body="{}")

    def sc(pg):
        pg.wait_for_selector("#alertes .ban"); pg.click("#alertes .ban"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue button:not(.non)")
        pg.wait_for_function("document.getElementById('retour').textContent.includes('Session')")
        return pg.inner_text("#retour")
    retour, erreurs, _, _ = _nav(sc, api=api)
    assert "Session requise" in retour and erreurs == []

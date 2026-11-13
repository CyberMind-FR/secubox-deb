# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3688 — /portal/ : un cadre dont le module n'est pas installé disparaît ; le tiret reste pour une mesure absente d'un
module présent. Présence lue dans le menu public du hub (celui du menu latéral), jamais déduite d'un 502 ou d'un 404.

Vrai navigateur, API simulée : Raspberry Pi sans secubox-metrics (menu relevé sur gk7 le 2026-11-12 ; metrics en 502,
cookie-audit en 404), box complète, metrics présent mais en panne, menu illisible ; 1400 et 420 px."""
import concurrent.futures
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "portal" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")

# Menu public relevé sur gk7 (Raspberry Pi 4) : secubox-metrics, waf, soc, actor et haproxy absents.
IDS_GK7 = ["acces", "ad-guard", "admin", "annuaire", "apercu", "auth", "companion", "dns-guard", "fleet", "freebox", "hardening",
           "health", "hub", "meshname", "mirrornet", "mobile", "nac", "netmodes", "p2p", "portal", "sbxid", "system", "tv-privacy",
           "users", "webfilter", "wireguard"]
IDS_COMPLETE = IDS_GK7 + ["metrics", "waf", "soc", "actor", "haproxy"]
CHEMINS = {"hub": "/", "actor": "/actor/"}


def menu(ids, actifs=None):
    items = [{"id": i, "path": CHEMINS.get(i, "/" + i + "/"), "installed": True, "active": (actifs or {}).get(i, True)} for i in ids]
    return {"categories": [{"id": "x", "name": "X", "items": items}], "total_installed": len(items), "total_active": len(items)}


PORTAIL = {"portal/verify": (200, {"valid": True, "username": "admin", "role": "admin", "expires": None,
                                   "session": {"login_time": "2026-11-12T08:12:00", "ip": "192.0.2.10"}}),
           "portal/status": (200, {"active_sessions": 1, "total_users": 2}),
           "portal/summary": (200, {"users": {"total": 2}, "sessions": {"active": 1}, "activity_24h": {"logins": 3},
                                    "webhooks_configured": 0, "recent_events": [{"timestamp": "2026-11-12T08:12:00", "event": "login"}]}),
           "portal/sessions": (200, {"count": 1, "sessions": [{"username": "admin", "role": "admin", "ip": "192.0.2.10",
                                                              "login_time": "2026-11-12T08:12:00"}]})}
METRICS = {"metrics/health/summary": (200, {"score": 94, "modules": {"waf": {"status": "ok"}, "haproxy": {"status": "ok"},
                                                                      "nginx": {"status": "ok"}, "system": {"status": "ok"}},
                                             "system": {"cpu": 20, "memory": 50, "disk": 40, "load": "0.1", "uptime": 3600},
                                             "waf": {"active_bans": 2, "alerts_today": 10, "blocked_pct": 3}}),
           "metrics/cert-status": (200, {"enabled": True, "summary": {"total": 3, "valid": 3, "expiring_soon": 0, "expiring_critical": 0, "expired": 0}}),
           "cookie-audit/summary": (200, {"enabled": True, "summary": {"host_count": 2, "violation_count": 0, "by_category": {}}}),
           "metrics/live-hosts": (200, {"enabled": True, "entries": [{"host": "www.exemple.test", "count": 5}]}),
           "metrics/visitor-origin": (200, {"enabled": True, "entries": [{"asn": 64496, "org": "Opérateur fictif", "count": 4}]})}
METRICS_502 = {k: (502, {"detail": "Bad Gateway"}) for k in METRICS if k.startswith("metrics/")}
CADRES = ["panSvc", "blocSys", "panWaf", "panCert", "panCook", "panHotes", "panAsn"]


def _avec_navigateur(scenario):
    sync_api = pytest.importorskip("playwright.sync_api")

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:      # navigateur absent : test sauté, pas en échec
                return ("skip", str(e))
            try:
                return ("ok", scenario(nav))
            finally:
                nav.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=240)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1]


def _portail(api, taille=(1400, 900)):
    def scenario(nav):
        ctx = nav.new_context(viewport={"width": taille[0], "height": taille[1]})
        pg = ctx.new_page()
        j = {"erreurs": [], "appels": []}
        pg.on("pageerror", lambda e: j["erreurs"].append(str(e)))

        def servir(r):
            chemin = r.request.url.split("http://t.test/", 1)[1].split("?")[0]
            if chemin.startswith("api/v1/"):
                j["appels"].append((r.request.method, chemin[len("api/v1/"):]))
                st, corps = api.get(chemin[len("api/v1/"):], (404, {"detail": "Not Found"}))
                return r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
            if chemin in ("portal/", "portal/index.html"):
                return r.fulfill(status=200, content_type="text/html", body=HTML)
            r.fulfill(status=404, content_type="text/plain", body="absent")
        pg.route("http://t.test/**", servir)
        pg.goto("http://t.test/portal/?embed=1")
        pg.wait_for_function("document.getElementById('heure').textContent && !document.getElementById('rafraichir').disabled "
                             "&& document.getElementById('evts').textContent", timeout=8000)
        pg.wait_for_timeout(200)
        r = {"caches": pg.evaluate("%s.filter(i => document.getElementById(i).hidden)" % json.dumps(CADRES)),
             "actif": pg.is_visible("#actif"), "actif_txt": pg.inner_text("#actif"),
             "tuiles": pg.evaluate("[...document.querySelectorAll('#tuiles .l')].map(e => e.textContent)"),
             "liens": pg.evaluate("[...document.querySelectorAll('#liens a')].map(a => a.getAttribute('href'))"),
             "svc_liens": pg.evaluate("[...document.querySelectorAll('#svcs a')].map(a => a.getAttribute('href'))"),
             "grilles": pg.evaluate("[...document.querySelectorAll('.app>.grille')].map(g => (g.hidden ? 'cachee' : '') + "
                                    "(g.classList.contains('n1') ? 'n1' : '') + (g.classList.contains('n2') ? 'n2' : ''))"),
             "texte": pg.inner_text(".app"), "evts": pg.is_visible("#evts"),
             "deb": pg.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")}
        ctx.close()
        return r, j
    return _avec_navigateur(scenario)


def test_raspberry_pi_sans_metrics_les_cadres_disparaissent_et_ne_sont_pas_appeles():
    api = {"hub/public/menu": (200, menu(IDS_GK7)), **METRICS_502, "cookie-audit/summary": (404, {"detail": "Not Found"}), **PORTAIL}
    r, j = _portail(api)
    assert r["caches"] == CADRES and not r["actif"]
    assert r["tuiles"] == ["Sessions actives", "Connexions 24 h"]
    assert r["liens"] == ["/system/"]                                            # seules les pages au menu
    assert r["grilles"] == ["n1", "", "cachee", "n1"] and r["evts"] and r["deb"]
    for t in ("Services en ligne", "Bans actifs", "Certificats valides", "Ressources", "Protection", "Cookies · RGPD",
              "Sites les plus visités", "Réseaux d’origine", "SANS MESURE", "indisponible"):
        assert t not in r["texte"], t                                            # innerText : les cadres masqués n'y sont pas
    assert not [c for _m, c in j["appels"] if c.startswith(("metrics/", "cookie-audit/"))]
    assert j["appels"][0] == ("GET", "hub/public/menu") and all(m == "GET" for m, _ in j["appels"]) and j["erreurs"] == []


def test_box_complete_rien_ne_change():
    for menu_api in ((200, menu(IDS_COMPLETE)), (500, {"detail": "erreur"}), (200, {"categories": [], "warming": True})):
        api = {"hub/public/menu": menu_api, **METRICS, **PORTAIL}
        r, j = _portail(api)
        assert r["caches"] == [] and r["actif"] and r["actif_txt"] == "SANTÉ 94 %", menu_api
        assert len(r["tuiles"]) == 6 and r["grilles"] == ["", "", "", ""], menu_api       # grille d'origine, aucune classe ajoutée
        assert r["liens"] == ["/metrics/", "/waf/", "/soc/", "/actor/", "/haproxy/", "/system/"]
        assert r["svc_liens"] == ["/waf/", "/haproxy/", "/system/"] and r["deb"] and j["erreurs"] == []
        assert ("GET", "cookie-audit/summary") in j["appels"]


def test_metrics_present_mais_en_panne_garde_ses_cadres_en_erreur():
    """Le module est au menu (même arrêté) : 502 sur ses routes = état d'erreur visible, jamais un cadre masqué."""
    api = {"hub/public/menu": (200, menu(IDS_COMPLETE, actifs={"metrics": False})), **METRICS_502,
           "cookie-audit/summary": (404, {"detail": "Not Found"}), **PORTAIL}
    r, j = _portail(api)
    assert r["caches"] == [] and r["actif"] and r["actif_txt"] == "SANS MESURE" and len(r["tuiles"]) == 6
    for t in ("Aucune mesure de ressources.", "Aucune mesure de protection.", "Suivi des certificats indisponible.",
              "Audit des cookies désactivé ou indisponible."):
        assert t in r["texte"], t
    assert "—" in r["texte"] and j["erreurs"] == []


@pytest.mark.parametrize("ids", [IDS_GK7, IDS_COMPLETE])
def test_420_px_sans_defilement_horizontal(ids):
    api = {"hub/public/menu": (200, menu(ids)), **METRICS, **PORTAIL}
    r, j = _portail(api, taille=(420, 900))
    assert r["deb"] and j["erreurs"] == []


def test_statique_presence_par_le_menu_du_hub_jamais_par_un_code_http():
    code = "".join(re.findall(r"<script>(.*?)</script>", HTML, flags=re.S))
    assert "/api/v1/hub/public/menu" in code and "menu.warming" in code
    assert not re.search(r"status\s*===?\s*(404|502)", code)                    # aucun cadre décidé sur un code d'erreur
    assert not re.search(r"method\s*:\s*['\"](POST|DELETE|PUT|PATCH)", HTML)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2677 — /dpi/, /ndpid/ (coque) et /mediaflow/ au profil Aurora : contrôles statiques + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGES = {
    "dpi": RACINE / "www" / "dpi" / "index.html",
    "ndpid": RACINE / "composants" / "ndpid" / "www" / "ndpid" / "index.html",
    "mediaflow": RACINE / "composants" / "mediaflow" / "www" / "mediaflow" / "index.html",
}
SRC = {k: v.read_text(encoding="utf-8") for k, v in PAGES.items()}
MO = 1048576


# ── statique ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("nom", sorted(PAGES))
def test_page_autonome_sans_dialogue_natif(nom):
    s = SRC[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert re.findall(r'<script src="([^"]+)"', s) == ["/shared/sidebar.js"]
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import|googleapis", s)
    assert "hybrid-dark" not in s and "crt-" not in s and "hybrid-skin" not in s
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "Math.random", "setItem"):
        assert interdit not in s, interdit
    assert "lorem" not in s.lower()
    assert "sbxVue" in s and f"onglet: '{nom}'" in s and "demo" in s.lower() and "embed" in s
    assert "min-height:100vh" not in s and "scrollHeight" not in s
    assert "container-type:inline-size" in s and 'lang="fr"' in s


@pytest.mark.parametrize("nom", sorted(PAGES))
def test_jeton_en_bearer_dans_un_try_catch(nom):
    s = SRC[nom]
    assert "localStorage.getItem('sbx_token')" in s and "'Bearer '" in s and "catch" in s


@pytest.mark.parametrize("nom", sorted(PAGES))
def test_chaque_tuile_porte_sa_definition(nom):
    tuiles = re.findall(r'<div class="tuile(?: [^"]*)?"[^>]*>', SRC[nom])
    assert tuiles and all('title="' in t for t in tuiles)


def test_dpi_ecritures_et_lectures_a_l_identique():
    s = SRC["dpi"]
    for r in ("api('/restart', 'POST')", "postJwt(API + '/rules/accept', s.proposed_rule)", "'/rules/ignore?domain=' + encodeURIComponent(s.domain)",
              "API + '/media/replay/' + encodeURIComponent(item.id)", "apiAuthed(API + '/media/buffer')", "api('/exfil')", "api('/history?days=' + JOURS)",
              "apiAuthed(API + '/usage')", "apiAuthed(API + '/lan_dns')", "apiAuthed(API + '/suggestions')", "apiAuthed(API + '/sessions')",
              "apiAuthed(API + '/countries')", "apiAuthed(API + '/media_types')", "X-SecuBox-Media"):
        assert r in s, r
    assert "method: 'POST'" in s and 'src="vue.html"' in s and "e.data.sbxdpiVue" in s     # api() (corps JSON) et postJwt()


def test_ndpid_coque_ne_ecrit_plus_et_garde_les_onglets():
    s = SRC["ndpid"]
    assert "'POST'" not in s and "const API_BASE = '/api/v1/ndpid'" in s
    assert 'role="tablist"' in s and s.count('role="tab"') == 5 and "aria-selected" in s


def test_mediaflow_ecritures_a_l_identique():
    s = SRC["mediaflow"]
    for r in ("ecrire('POST', '/clone', { url: r.url, audio_url: r.audio_url || null, kind: r.kind })", "ecrire('DELETE', '/library/' + encodeURIComponent(id))",
              "api('/status')", "api('/streams')", "api('/services')", "api('/discovered')", "api('/library')", "api('/clone/jobs')", "'/download/'"):
        assert r in s, r


# ── navigateur ──────────────────────────────────────────────────────────────
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
SVC = lambda nom, cat, up, down, fl: {"service": nom, "category": cat, "dst": "198.51.100.7", "proto": "TLS", "up_bytes": up, "down_bytes": down, "flows": fl}  # noqa: E731
EXFIL = {
    "generated_at": NOW - 10, "alert_count": 2, "window_days": 7,
    "engine": {"name": "ndpiReader · R3 exfil", "service": "secubox-dpi-flowcap", "alive": True, "last_window_s": 12},
    "devices": [
        {"device": "aaaaaaaa11111111", "flows": 100, "up_bytes": 3 * MO, "down_bytes": 9 * MO, "by_category": {"cloud": 5, "media": 4}, "alerts": [{}],
         "services": [SVC("Nuage", "cloud", 2 * MO, MO, 5), SVC("Vidéo", "media", MO, 8 * MO, 4)]},
        {"device": "bbbbbbbb22222222", "flows": 50, "up_bytes": MO, "down_bytes": 3 * MO, "by_category": {"game": 3}, "alerts": [],
         "services": [SVC("Jeu", "game", MO, 3 * MO, 3)]}],
    "alerts": [{"kind": "exfil_volume", "device": "aaaaaaaa11111111", "service": "Nuage", "category": "cloud", "dst": "198.51.100.7", "detail": "gros envoi", "up_bytes": 2 * MO, "ts": NOW - 60},
               {"kind": "new_cloud", "device": "aaaaaaaa11111111", "dst": "198.51.100.8", "up_bytes": 1, "ts": NOW - 90}],
    "top_apps": [{"name": "AppUne", "bytes": 5 * MO, "flows": 7}], "top_protocols": [{"name": "TLS", "bytes": 9 * MO, "flows": 12}],
    "active_flows": [{"service": "Vidéo", "category": "media", "dst": "198.51.100.9", "proto": "QUIC", "up_bytes": 2 * MO, "down_bytes": 6 * MO}],
}
HIST = {"days": [{"day": "2026-10-10", "flows": 10, "up_bytes": MO, "down_bytes": 4 * MO, "alerts": 0, "devices": 2},
                 {"day": "2026-10-11", "flows": 30, "up_bytes": 2 * MO, "down_bytes": 6 * MO, "alerts": 1, "devices": 2}]}
NDP_P = {"protocols": [{"protocol": "TLS", "flow_count": 8, "bytes_total": 4 * MO}]}
NDP_A = {"applications": [{"application": "AppNd", "flow_count": 3, "bytes_total": MO}]}
MF_ST = {"running": True, "video_streams": 3, "audio_streams": 1, "bandwidth_mbps": 14.6, "active_clients": 2}


def ouvre(navigateur, chemin_page, nom, routes, taille=None, jeton=None):
    """Sert la page sous http://sbx.test/<chemin_page> ; routes : {chemin d'API sans requête: (statut, corps)}."""
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script(f"try {{ localStorage.setItem('sbx_token', {json.dumps(jeton)}) }} catch (e) {{}}")
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        u = urlsplit(r.request.url)
        if u.path.startswith("/shared/"):
            r.fulfill(status=200, content_type="text/css" if u.path.endswith(".css") else "application/javascript", body="")
        elif u.path.startswith("/api/"):
            appels.append((r.request.method, u.path + ("?" + u.query if u.query else ""), r.request.post_data, r.request.headers.get("authorization", "")))
            st, corps = routes.get(u.path, (200, {"success": True}) if r.request.method != "GET" else (404, {}))
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        elif u.path.rstrip("/") == "/" + chemin_page.split("?")[0].strip("/"):
            r.fulfill(status=200, content_type="text/html", body=SRC[nom])
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/" + chemin_page)
    return ctx, p, erreurs, appels


DPI = {"/api/v1/dpi/exfil": (200, EXFIL), "/api/v1/dpi/history": (200, HIST), "/api/v1/ndpid/top/protocols": (200, NDP_P),
       "/api/v1/ndpid/top/applications": (200, NDP_A), "/api/v1/mediaflow/status": (200, MF_ST)}
TUILES = ("#tFlux", "#tUp", "#tDown", "#tTotal", "#tPart", "#tTerm", "#tCat", "#tAlert", "#tLUp", "#tLDown", "#tLFlux", "#tVid", "#tAud", "#tMbps", "#tCli")


def attend_dpi(p):
    p.wait_for_function("document.getElementById('tFlux').textContent !== '—' || document.getElementById('session').hidden === false")
    p.wait_for_function("document.getElementById('tVid').textContent !== '—' || document.getElementById('session').hidden === false")


def test_dpi_tuiles_de_synthese_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "dpi/", "dpi", DPI, jeton="jeton-admin")
    attend_dpi(p)
    t = {i: p.inner_text(i) for i in TUILES}
    assert t["#tFlux"] == "150" and t["#tUp"] == "4,00 Mo" and t["#tDown"] == "12,0 Mo" and t["#tTotal"] == "16,0 Mo"
    assert t["#tPart"] == "25 %" and t["#tTerm"] == "2" and t["#tCat"] == "3" and t["#tAlert"] == "2"
    assert t["#tLUp"] == "2,00 Mo" and t["#tLDown"] == "6,00 Mo" and t["#tLFlux"] == "1"
    assert t["#tVid"] == "3" and t["#tAud"] == "1" and t["#tMbps"] == "14,60" and t["#tCli"] == "2"
    assert p.inner_text("#etat") == "● R3 ACTIF" and err == []
    assert "7 jours" in p.inner_text("#srcCumul") and "non réglable" in p.inner_text("#srcCumul")
    assert all(a[3] == "Bearer jeton-admin" for a in appels)                  # jeton en Bearer sur chaque lecture
    assert all(a[0] == "GET" for a in appels)                                 # lecture seule tant qu'on ne clique pas
    ctx.close()


def test_dpi_blocs_graphiques_et_listes(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "dpi/", "dpi", DPI)
    attend_dpi(p)
    p.wait_for_selector("#courbe svg path.tr")
    assert p.locator("#courbe svg path.tr").count() == 2 and p.locator("#courbe svg circle").count() == 4      # 2 séries x 2 jours mesurés
    assert p.locator("#dpi-timeline svg rect").count() == 2
    assert p.locator("#donut svg circle").count() == 1 + 3                      # fond + cloud, media, game
    leg = p.inner_text("#svc-categories")
    assert "media" in leg and "cloud" in leg and "game" in leg and "9,00 Mo" in leg
    assert "TLS" in p.inner_text("#top-protocols") and "AppUne" in p.inner_text("#top-apps")
    assert "Vidéo" in p.inner_text("#topDest") and "1 terminal" in p.inner_text("#topDest")
    assert "aaaaaaaa…" in p.inner_text("#bandwidth-devices") and "EXFIL ×1" in p.inner_text("#bandwidth-devices") and "RAS" in p.inner_text("#bandwidth-devices")
    assert "2 ALERTES" == p.inner_text("#exfil-badge") and "ENVOI MASSIF" in p.inner_text("#exfil-alerts")
    assert "AppNd" in p.inner_text("#ndApps") and "TLS" in p.inner_text("#ndProto")
    assert err == []
    ctx.close()


def test_dpi_fenetres_de_temps_selectionnables(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "dpi/", "dpi", DPI)
    attend_dpi(p)
    p.click("[data-j='30']")
    p.wait_for_function("document.querySelector(\"[data-j='30']\").getAttribute('aria-pressed') === 'true'")
    p.wait_for_function("document.getElementById('srcHist').textContent.includes('sur 30 demandés')")
    assert any(a[1] == "/api/v1/dpi/history?days=30" for a in appels)
    p.click("[data-h='6']")
    p.wait_for_function("document.getElementById('srcNd').textContent.includes('6 h')")
    assert any(a[1].startswith("/api/v1/ndpid/top/protocols?hours=6") for a in appels)
    ctx.close()


def test_dpi_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in DPI}
    ctx, p, err, _ = ouvre(navigateur, "dpi/", "dpi", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in TUILES] == ["—"] * len(TUILES) and err == []
    ctx.close()


def test_dpi_collecteur_vide_ne_met_pas_de_zero_au_jugé(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "dpi/", "dpi", {"/api/v1/dpi/exfil": (200, {}), "/api/v1/mediaflow/status": (200, {"running": False, "error": "x", "video_streams": 0})})
    p.wait_for_function("document.getElementById('etat').textContent !== 'Chargement…'")
    p.wait_for_timeout(300)
    assert [p.inner_text(i) for i in ("#tFlux", "#tUp", "#tTotal", "#tPart", "#tVid", "#tMbps")] == ["—"] * 6 and err == []
    ctx.close()


def test_dpi_redemarrage_demande_confirmation_et_garde_le_meme_appel(navigateur):
    routes = {**DPI, "/api/v1/dpi/restart": (200, {"success": False, "retired": True})}
    ctx, p, _, appels = ouvre(navigateur, "dpi/", "dpi", routes, jeton="t")
    attend_dpi(p)
    p.click("#btnRestart")
    assert p.is_visible("#confirmeRestart") and not [a for a in appels if a[0] == "POST"]
    p.click("#noRestart")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#btnRestart"); p.click("#okRestart")
    p.wait_for_function("document.getElementById('rRestart').textContent.includes('retiré')")
    post = [a for a in appels if a[0] == "POST"]
    assert len(post) == 1 and post[0][1] == "/api/v1/dpi/restart" and post[0][3] == "Bearer t"
    ctx.close()


def test_dpi_apprentissage_valider_et_ignorer_memes_appels(navigateur):
    routes = {**DPI, "/api/v1/dpi/suggestions": (200, [{"domain": "x.exemple.test", "reason": "r", "confidence": 77, "proposed_rule": {"domain": "x.exemple.test", "app": "X"}}]),
              "/api/v1/dpi/rules/accept": (200, {"count": 4}), "/api/v1/dpi/rules/ignore": (200, {"ok": True})}
    ctx, p, _, appels = ouvre(navigateur, "dpi/", "dpi", routes)
    p.wait_for_selector("#dpi-learning button")
    p.get_by_text("✓ Créer la règle").click()
    p.wait_for_function("document.getElementById('rLearn').textContent.includes('4 au total')")
    assert ("POST", "/api/v1/dpi/rules/accept", '{"domain":"x.exemple.test","app":"X"}', "") in appels
    p.get_by_text("Ignorer").click()
    p.wait_for_function("document.getElementById('rLearn').textContent.includes('ignoré')")
    assert any(a[0] == "POST" and a[1] == "/api/v1/dpi/rules/ignore?domain=x.exemple.test" for a in appels)
    ctx.close()


def test_dpi_texte_piege_inoffensif(navigateur):
    piege = "<img src=x onerror=window.__pwn=1>"
    ex = json.loads(json.dumps(EXFIL))
    ex["devices"][0]["services"][0]["service"] = piege
    ex["top_apps"][0]["name"] = piege
    ctx, p, err, _ = ouvre(navigateur, "dpi/", "dpi", {**DPI, "/api/v1/dpi/exfil": (200, ex)})
    attend_dpi(p)
    assert piege in p.inner_text("#top-apps") and p.evaluate("window.__pwn === undefined") and p.locator("img").count() == 0 and err == []
    ctx.close()


def test_dpi_demonstration_annoncee_sans_aucun_appel_d_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "dpi/?demo=1", "dpi", {})
    p.wait_for_function("document.getElementById('tFlux').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tVid") == "3" and p.locator("#courbe svg path.tr").count() == 2
    p.click("#btnRestart"); p.click("#okRestart")
    p.wait_for_function("document.getElementById('rRestart').textContent.includes('inerte')")
    p.get_by_text("✓ Créer la règle").click()
    p.wait_for_function("document.getElementById('rLearn').textContent.includes('inerte')")
    p.click("[data-j='7']"); p.wait_for_function("document.querySelectorAll('#courbe svg circle').length === 14")
    assert appels == [] and err == []
    ctx.close()


def test_dpi_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "dpi/?demo=1&embed=1", "dpi", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tFlux').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    p.evaluate("window.__h = null; addEventListener('message', e => { if (e.data && e.data.sbxVue) window.__h = e.data; }); dispatchEvent(new Event('resize'))")   # hors iframe, parent === window
    p.wait_for_function("window.__h !== null")
    h = p.evaluate("window.__h")
    assert h["onglet"] == "dpi" and 300 < h["sbxVue"] < 20000
    ctx.close()


# ── ndpid (coque) ───────────────────────────────────────────────────────────
ND = {"/api/v1/ndpid/status": (200, {"daemon": {"running": True, "source": "nDPId"}, "database": {"total_fingerprints": 12, "risks_24h": 3}}),
      "/api/v1/ndpid/flows": (200, {"count": 7, "flows": []})}


def test_ndpid_tuiles_onglets_et_cadre(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "ndpid/", "ndpid", ND, jeton="jt")
    p.wait_for_function("document.getElementById('flows-active').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#daemon-status", "#flows-active", "#fingerprints-count", "#risks-24h")] == ["Actif", "7", "12", "3"]
    assert p.get_attribute("#pageFrame", "src") == "flux.html?embed=1" and p.get_attribute("#tab-flows", "aria-selected") == "true"
    for onglet, page in (("protocols", "protocoles"), ("fingerprints", "empreintes"), ("risks", "risques"), ("settings", "reglages")):
        p.click(f"#tab-{onglet}")
        assert p.get_attribute("#pageFrame", "src") == f"{page}.html?embed=1" and p.get_attribute(f"#tab-{onglet}", "aria-selected") == "true"
    assert all(a[0] == "GET" and a[3] == "Bearer jt" for a in appels) and err == []
    # l'hôte ajuste la hauteur du cadre d'après le message de l'onglet courant
    p.evaluate("postMessage({sbxNdpidVue: 900, onglet: 'reglages'}, location.origin)")
    p.wait_for_function("document.getElementById('pageFrame').style.height === '904px'")
    ctx.close()


def test_ndpid_repli_ndpireader_et_sans_session(navigateur):
    st = {"daemon": {"running": True, "source": "ndpiReader/dpi"}, "database": {"total_fingerprints": 0, "risks_24h": 0}}
    ctx, p, _, _ = ouvre(navigateur, "ndpid/", "ndpid", {**ND, "/api/v1/ndpid/status": (200, st)})
    p.wait_for_selector("#ndpid-source:not([hidden])")
    assert "ndpiReader" in p.inner_text("#ndpid-source") and "JA3" in p.inner_text("#ndpid-source")
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "ndpid/", "ndpid", {k: (401, {}) for k in ND})
    p.wait_for_selector("#session:not([hidden])")
    assert "connexion requise" in p.inner_text("#ndpid-erreur").lower() and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#daemon-status", "#flows-active", "#fingerprints-count", "#risks-24h")] == ["—"] * 4 and err == []
    ctx.close()


def test_ndpid_demo_et_telephone(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "ndpid/?demo=1&embed=1", "ndpid", {}, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('flows-active').textContent !== '—'")
    assert p.is_visible("#demo") and p.get_attribute("#pageFrame", "src") == "flux.html?embed=1&demo=1"
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and appels == [] and err == [] and not p.is_visible("#sidebar")
    ctx.close()


# ── mediaflow ───────────────────────────────────────────────────────────────
MF = {"/api/v1/mediaflow/status": (200, MF_ST),
      "/api/v1/mediaflow/streams": (200, {"streams": [{"client_ip": "192.0.2.10", "type": "video", "service": "Vidéo", "bandwidth": "9.40 Mbps", "duration": "—"}]}),
      "/api/v1/mediaflow/services": (200, {"services": [{"name": "Vidéo", "streams": 3, "bandwidth": "9 Mbps", "percent": 80}]}),
      "/api/v1/mediaflow/discovered": (200, {"catcher": True, "downloader": "yt-dlp", "discovered": [
          {"host": "cdn.exemple.test", "kind": "video", "url": "https://cdn.exemple.test/v.mp4", "hits": 4},
          {"host": "evil.exemple.test", "kind": "audio", "url": "javascript:window.__pwn=1", "hits": 1}]}),
      "/api/v1/mediaflow/library": (200, {"library": []}),
      "/api/v1/mediaflow/clone/jobs": (200, {"jobs": [{"id": "j1", "url": "u", "title": "clip.mp4", "status": "done", "bytes": 5 * MO}]})}


def test_mediaflow_tuiles_et_tableaux(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "mediaflow/", "mediaflow", MF, jeton="jm")
    p.wait_for_selector("#libraryTable tr td:has-text('clip.mp4')")
    assert [p.inner_text(i) for i in ("#videoStreams", "#audioStreams", "#bandwidth", "#activeClients")] == ["3", "1", "14,6", "2"]
    assert "192.0.2.10" in p.inner_text("#streamsTable") and "Vidéo" in p.inner_text("#servicesTable") and "5,0 Mo" in p.inner_text("#libraryTable")
    assert p.inner_text("#etat") == "ACTIF" and err == []
    assert {a[1] for a in appels} == {"/api/v1/mediaflow/" + x for x in ("status", "streams", "services", "discovered", "library", "clone/jobs")}
    assert all(a[3] == "Bearer jm" for a in appels)
    ctx.close()


def test_mediaflow_lien_javascript_jamais_actif(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "mediaflow/", "mediaflow", MF)
    p.wait_for_selector("#discoveredTable td.url")
    assert p.locator("#discoveredTable a").count() == 1 and "javascript:" in p.inner_text("#discoveredTable")
    assert p.evaluate("window.__pwn === undefined")
    ctx.close()


def test_mediaflow_cloner_meme_corps_et_supprimer_avec_confirmation(navigateur):
    routes = {**MF, "/api/v1/mediaflow/clone": (200, {"id": "x", "status": "queued"}), "/api/v1/mediaflow/library/j1": (200, {"success": True})}
    ctx, p, _, appels = ouvre(navigateur, "mediaflow/", "mediaflow", routes)
    p.wait_for_selector("#discoveredTable td.act")
    p.locator("#discoveredTable tr").first.get_by_text("Cloner").click()
    p.wait_for_function("document.getElementById('rClone').textContent.includes('file')")
    clone = [a for a in appels if a[0] == "POST"][0]
    assert clone[1] == "/api/v1/mediaflow/clone" and json.loads(clone[2]) == {"url": "https://cdn.exemple.test/v.mp4", "audio_url": None, "kind": "video"}
    p.locator("#libraryTable tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]                          # pas avant la confirmation
    p.locator("#libraryTable tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#libraryTable tr").first.get_by_text("Supprimer").click()
    p.locator("#libraryTable tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rLib').textContent.includes('supprimé')")
    assert ("DELETE", "/api/v1/mediaflow/library/j1", None, "") in appels
    assert p.get_attribute("#libraryTable a[download]", "href") == "/api/v1/mediaflow/download/j1"
    ctx.close()


def test_mediaflow_sans_session_et_statut_en_erreur(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "mediaflow/", "mediaflow", {k: (401, {}) for k in MF})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and [p.inner_text(i) for i in ("#videoStreams", "#audioStreams", "#bandwidth", "#activeClients")] == ["—"] * 4 and err == []
    ctx.close()
    # l'API renvoie 0 avec « error » quand le DPI est injoignable : ce 0 n'est pas une mesure
    ctx, p, err, _ = ouvre(navigateur, "mediaflow/", "mediaflow", {**MF, "/api/v1/mediaflow/status": (200, {"running": False, "error": "x", "video_streams": 0, "audio_streams": 0, "bandwidth_mbps": 0.0, "active_clients": 0})})
    p.wait_for_selector("#libraryTable td")
    assert [p.inner_text(i) for i in ("#videoStreams", "#bandwidth")] == ["—", "—"] and p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


def test_mediaflow_demo_inerte_et_telephone(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "mediaflow/?demo=1&embed=1", "mediaflow", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#discoveredTable td.act")
    assert p.is_visible("#demo")
    p.locator("#discoveredTable tr").first.get_by_text("Cloner").click()
    p.wait_for_function("document.getElementById('rClone').textContent.includes('inerte')")
    p.locator("#libraryTable tr").first.get_by_text("Supprimer").click(); p.locator("#libraryTable tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rLib').textContent.includes('inerte')")
    assert appels == [] and err == [] and p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and not p.is_visible("#sidebar")
    ctx.close()

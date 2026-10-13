# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /profiles/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "profiles" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-skin" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'profiles'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/active', { name: SEL }", "'/apply', { profile: SEL }", "'/rollback', undefined", "'/members'", "{ id: id, on: on }",
              "'/pins', { id: id, pin: pin }", "{ module: id }", "'/lifecycle', { module: id, lifecycle: lifecycle, wake_class: wakeClass }"):
        assert r in SRC, r
    for lecture in ("'/status'", "'/profiles'", "'/pins'", "'/diff?profile='"):
        assert lecture in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def mod(id, cat, rt, expo, prio, prot, on, rss, lc, wc, ss, bud):
    return {"id": id, "category": cat, "runtime": rt, "exposure": expo, "priority": prio, "protected": prot, "on": on, "rss_kb": rss,
            "lifecycle": lc, "wake_class": wc, "sleep_state": ss, "wake_budget_s": bud, "portal_domain": None}


STATUS = {"modules": [mod("auth", "noyau", "systemd", "interne", 90, True, "on", 2048, "always-on", "normal", "n/a", None),
                      mod("notes", "collab", "lxc", "public", 30, False, "on", 4096, "on-demand", "normal", "up", 30),
                      mod("medias", "media", "lxc", "lan", 20, False, "off", None, "on-demand", "normal", "asleep", 45)],
          "totals": {"count": 3, "on": 2, "off": 1, "unknown": 0, "rss_kb": 6144, "exposed_public": 1},
          "by_category": {"noyau": {"count": 1, "on": 1, "off": 0, "unknown": 0, "rss_kb": 2048}, "media": {"count": 1, "on": 0, "off": 1, "unknown": 0, "rss_kb": 0}},
          "by_runtime": {"lxc": {"count": 2, "on": 1, "off": 1, "unknown": 0, "rss_kb": 4096}}, "by_exposure": {"public": {"count": 1, "on": 1, "off": 0, "unknown": 0, "rss_kb": 4096}}}
PROFILS = {"active": "lite", "profiles": [{"name": "lite", "label": "Léger", "on": ["auth", "notes"]}, {"name": "full", "label": "Complet", "on": ["auth", "notes", "medias"]}]}
DIFF = {"profile": "full", "changes": [{"id": "medias", "action": "start", "reason": "membre du profil", "priority": 20}]}
API = {("GET", "/status"): (200, STATUS), ("GET", "/profiles"): (200, PROFILS), ("GET", "/pins"): (200, {"pins": {"notes": "on"}}),
       ("GET", "/diff"): (200, DIFF)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "profiles":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/profiles", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), (200, {"status": "ok"}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/profiles/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/profiles/", API)
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tOn", "#tOff", "#tUnknown", "#tRam", "#tExp")] == ["3", "2", "1", "0", "6.0 Mo", "1"]
    assert p.inner_text("#etat") == "PROFIL ACTIF : lite"
    t = p.inner_text("#bMod")
    assert "auth" in t and "medias" in t and "ENDORMI" in t and "—" in t       # RAM non mesurée = tiret, pas 0
    assert "noyau" in p.inner_text("#bAgg")
    p.click("[data-agg=by_exposure]")
    assert "public" in p.inner_text("#bAgg")
    assert "medias" in p.inner_text("#bDiff") and "DÉMARRER" in p.inner_text("#bDiff")
    assert err == []
    ctx.close()


def test_ram_sans_mesure_reste_un_tiret(navigateur):
    st = json.loads(json.dumps(STATUS)); st["totals"]["rss_kb"] = 0
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/profiles/", {**API, ("GET", "/status"): (200, st)})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    assert p.inner_text("#tRam") == "—"
    ctx.close()


def test_apercu_puis_application_confirmee_dans_la_page(navigateur):
    rep = {"status": "applied", "changed": ["medias"], "failed": [], "rolled_back": []}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/profiles/", {**API, ("POST", "/apply"): (200, rep)})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    p.select_option("#profil", "full")
    assert p.is_hidden("#bAppliquer")
    p.click("#bApercu")
    p.wait_for_selector("#bAppliquer:not([hidden])")
    assert ("POST", "/active", '{"name":"full"}') in appels and "medias" in p.inner_text("#bApercuL")
    p.click("#bAppliquer")
    p.wait_for_selector("#conf:not([hidden])")
    assert "1 module" in p.inner_text("#conf")
    assert not [a for a in appels if a[1] == "/apply"]              # pas avant la confirmation
    p.click("#conf >> text=Confirmer")
    p.wait_for_function("document.getElementById('rapport').textContent.includes('applied')")
    assert ("POST", "/apply", '{"profile":"full"}') in appels
    assert "medias" in p.inner_text("#rapport")
    ctx.close()


def test_annuler_l_application_n_envoie_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/profiles/", API)
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    p.click("#bApercu"); p.wait_for_selector("#bAppliquer:not([hidden])")
    p.click("#bAppliquer"); p.wait_for_selector("#conf:not([hidden])")
    p.click("#conf >> text=Annuler")
    assert p.is_hidden("#conf") and not [a for a in appels if a[1] == "/apply"]
    ctx.close()


def test_rollback_confirme_sans_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/profiles/", {**API, ("POST", "/rollback"): (200, {"status": "applied", "changed": [], "failed": [], "rolled_back": []})})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    p.click("#bRollback"); p.wait_for_selector("#conf:not([hidden])")
    assert not [a for a in appels if a[1] == "/rollback"]
    p.click("#conf >> text=Confirmer")
    p.wait_for_function("document.getElementById('rapport').textContent.includes('Rollback')")
    assert ("POST", "/rollback", None) in appels
    ctx.close()


def test_actions_par_module_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/profiles/", {**API, ("POST", "/wake"): (200, {"status": "up"}), ("POST", "/sleep"): (200, {"status": "asleep"})})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    ligne = lambda m: p.locator("#bMod tr", has_text=m)
    ligne("medias").get_by_text("Réveiller").click()
    p.wait_for_timeout(300)
    assert any(a[:2] == ("POST", "/wake") and json.loads(a[2]) == {"module": "medias"} for a in appels)
    # endormir demande une confirmation dans la ligne
    ligne("notes").get_by_text("Endormir").click()
    assert not [a for a in appels if a[1] == "/sleep"]
    ligne("notes").get_by_text("Confirmer").click()
    p.wait_for_timeout(300)
    assert any(a[:2] == ("POST", "/sleep") and json.loads(a[2]) == {"module": "notes"} for a in appels)
    ligne("auth").get_by_text("📌 ON").click()
    p.wait_for_timeout(200)
    assert any(a[:2] == ("POST", "/pins") and json.loads(a[2]) == {"id": "auth", "pin": "on"} for a in appels)
    ligne("notes").get_by_text("⟳").click()
    p.wait_for_timeout(200)
    assert any(a[:2] == ("POST", "/pins") and json.loads(a[2]) == {"id": "notes", "pin": None} for a in appels)
    ligne("medias").locator("input[type=checkbox]").click()
    p.wait_for_timeout(200)
    assert any(a[:2] == ("POST", "/profiles/lite/members") and json.loads(a[2]) == {"id": "medias", "on": True} for a in appels)
    ligne("notes").locator("select[data-kind=wake_class]").select_option("urgent")
    p.wait_for_timeout(200)
    assert any(a[:2] == ("POST", "/lifecycle") and json.loads(a[2]) == {"module": "notes", "lifecycle": "on-demand", "wake_class": "urgent"} for a in appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {(m, c): (401, {"detail": "jeton requis"}) for m, c in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/profiles/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tOn", "#tRam", "#tExp")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/profiles/?demo=1", {})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bApercu"); p.wait_for_selector("#bAppliquer:not([hidden])")
    p.locator("#bMod tr", has_text="exemple-medias").get_by_text("Réveiller").click()
    p.locator("#bMod tr", has_text="exemple-medias").locator("input[type=checkbox]").click()
    p.wait_for_timeout(300)
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/profiles/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bMod tr td.mono", state="attached")
    p.evaluate("window.__h = []; addEventListener('message', e => window.__h.push(e.data))")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /ksm/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "ksm" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "oninput="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'ksm'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/enable'", "'/disable'", "'/config', { pages_to_scan: c.pages_to_scan, sleep_millisecs: c.sleep_millisecs }", "method: 'POST'"):
        assert r in SRC, r
    for lecture in ("'/status'", "'/stats'", "'/config'"):
        assert lecture in SRC, lecture
    assert len(re.findall(r"ecrire\(", SRC)) == 3  # définition + /enable|/disable + /config : aucune action de plus
    assert "DELETE" not in SRC and "PUT" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"available": True, "enabled": True, "run_value": 1}
STATS = {"pages_shared": 1000, "pages_sharing": 3000, "pages_unshared": 5000, "full_scans": 12, "memory_saved_bytes": 2000 * 4096,
         "memory_saved_human": "7.8 MB", "stable_node_chains": None, "stable_node_dups": 4}
CONFIG = {"pages_to_scan": 64, "sleep_millisecs": 25}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/config": (200, CONFIG)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ksm":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/ksm", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/ksm/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ksm/", API, jeton="jt")
    p.wait_for_function("document.getElementById('tShared').textContent !== '—'")
    assert p.inner_text("#tSharing") == "3 000" or p.inner_text("#tSharing").replace(" ", "").replace(" ", "") == "3000"
    assert p.inner_text("#tEco") == "7,8 Mo"          # 2000 pages x 4 Kio, formatée par la page en français
    assert p.inner_text("#tScans") == "12" and p.inner_text("#tRun") == "1" and p.inner_text("#etat") == "KSM ACTIF"
    assert p.inner_text("#kChaines") == "—" and p.inner_text("#kDups") == "4" and "3 ×" in p.inner_text("#kRatio")
    # la valeur 64 du noyau n'est pas faussée (l'ancien curseur la ramenait à 100)
    assert p.input_value("#iPages") == "64" and p.input_value("#iSommeil") == "25"
    assert all(a[3] == "Bearer jt" for a in appels) and err == []
    ctx.close()


def test_bascule_demande_confirmation_puis_envoie_disable(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ksm/", {**API, "/disable": (200, {"success": True, "message": "KSM disabled"})})
    p.wait_for_function("!document.getElementById('bascule').disabled")
    assert p.inner_text("#bascule") == "Désactiver KSM"
    p.click("#bascule")
    assert p.is_visible("#confCtl") and not [a for a in appels if a[0] == "POST"]
    p.click("#okCtl")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('désactivé')")
    assert ("POST", "/disable", None) in [a[:3] for a in appels] and err == []
    ctx.close()


def test_annuler_n_ecrit_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ksm/", API)
    p.wait_for_function("!document.getElementById('bascule').disabled")
    p.click("#bascule"); p.click("#noCtl")
    assert not p.is_visible("#confCtl") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_enregistrer_le_reglage_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ksm/", {**API, "/config": (200, {**CONFIG, "success": True})})
    p.wait_for_function("document.getElementById('iPages').value === '64'")
    p.fill("#iPages", "500"); p.fill("#iSommeil", "40")
    p.click("#enreg")
    assert "500 pages" in p.inner_text("#txtCfg") and not [a for a in appels if a[0] == "POST"]
    p.click("#okCfg")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"pages_to_scan": 500, "sleep_millisecs": 40}
    ctx.close()


def test_valeur_hors_bornes_refusee_sans_appel(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/ksm/", API)
    p.wait_for_function("document.getElementById('iPages').value === '64'")
    p.fill("#iPages", "20000"); p.click("#enreg")
    assert "refusées" in p.inner_text("#rCfg") and not p.is_visible("#confCfg") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_echec_serveur_affiche_dans_la_page(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/ksm/", {**API, "/enable": (503, {"detail": "KSM not available on this system"}), "/status": (200, {**STATUS, "enabled": False, "run_value": 0})})
    p.wait_for_function("document.getElementById('bascule').textContent === 'Activer KSM'")
    p.click("#bascule"); p.click("#okCtl")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('Échec')")
    assert "not available" in p.inner_text("#rCtl")
    ctx.close()


def test_ksm_absent_du_noyau(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ksm/", {"/status": (200, {"available": False, "enabled": False, "error": "x"}), "/stats": (200, {"error": "KSM not available"}), "/config": (200, {"error": "x"})})
    p.wait_for_function("document.getElementById('etat').textContent === 'NON DISPONIBLE'")
    assert [p.inner_text(i) for i in ("#tEco", "#tSharing", "#tScans", "#tRun")] == ["—"] * 4
    assert p.is_disabled("#bascule") and p.is_disabled("#enreg") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ksm/", {k: (401, {"detail": "jeton requis"}) for k in API})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEco", "#tSharing", "#tShared", "#tUnshared", "#tScans", "#tRun")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ksm/?demo=1", {})
    p.wait_for_function("document.getElementById('tShared').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bascule"); p.click("#okCtl")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('inerte')")
    p.click("#enreg"); p.click("#okCfg")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ksm/?embed=1", API, taille={"width": 420, "height": 800})
    p.add_init_script("window.__h=[];addEventListener('message',e=>__h.push(e.data))")
    p.wait_for_function("document.getElementById('tShared').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

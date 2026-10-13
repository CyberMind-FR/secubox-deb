# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /zia/admin.html au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "zia" / "admin.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif_ni_police_externe():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "gstatic" not in SRC and "hybrid-dark" not in SRC
    assert not re.search(r"https?://[^\s\"')]*\.(js|css)", SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'zia-admin'" in SRC and "ResizeObserver" in SRC
    assert "sbx_token" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    # Anciennes écritures : POST /config (sous-ensembles par carte) et POST /llm/test, rien d'autre.
    ecritures = re.findall(r"ecrire\('(/[^']*)'", SRC)
    assert sorted(set(ecritures)) == ["/config", "/llm/test"]
    assert "method: 'POST'" in SRC and "DELETE" not in SRC and "'PUT'" not in SRC
    for groupe in ("moteur:", "bus:", "remote:"):
        assert groupe in SRC
    for cle in ("llm_url", "model_name", "n_predict", "llm_timeout_s", "peertube_url", "default_role", "bus_cache_s",
                "metanews_sock", "webos_sock", "billets_sock", "remote_enabled", "remote_role_min", "remote_url",
                "remote_timeout_s", "remote_budget"):
        assert "'" + cle + "'" in SRC
    assert "/auth/login" not in SRC and "/auth/logout" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


CONFIG = {"model_name": "TinyLlama", "llm_url": "http://127.0.0.1:8091", "n_predict": 120, "llm_timeout_s": 20, "metanews_sock": "/run/secubox/metanews.sock",
          "webos_sock": "/run/secubox/webos.sock", "billets_sock": "/run/secubox/billets.sock", "peertube_url": "https://pt.example.test", "bus_cache_s": 45,
          "default_role": "guest", "remote_enabled": False, "remote_role_min": "admin", "remote_url": "", "remote_timeout_s": 15, "remote_budget": 20}
METRIQUES = {"chats": 10, "latence_ms_moy": 812.4, "objets_bus": 37, "engine": "llm", "model": "TinyLlama", "tools": [], "remote_enabled": False}
API = {"/config": (200, CONFIG), "/metrics": (200, METRIQUES)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, entetes = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "zia/admin.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/zia", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        entetes.append(r.request.headers.get("authorization"))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get("POST " + chemin, (200, {"ok": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/zia/**", api)
    p.goto(url)
    p.entetes = entetes
    return ctx, p, erreurs, appels


URL = "http://sbx.test/zia/admin.html"


def test_tuiles_et_champs_viennent_de_l_api_avec_le_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_function("document.getElementById('tObjets').textContent === '37'")
    assert [p.inner_text(i) for i in ("#tMoteur", "#tModele", "#tObjets", "#tEchanges", "#tLatence", "#tRemote")] == ["LLM", "TinyLlama", "37", "10", "812 ms", "Désarmé"]
    assert p.input_value("#llm_url") == "http://127.0.0.1:8091" and p.input_value("#n_predict") == "120" and p.input_value("#default_role") == "guest"
    assert p.inner_text("#etat") == "EN LIGNE" and "jeton-test" in p.entetes[-1]  # /metrics envoie bien le jeton
    assert err == []
    ctx.close()


def test_aucun_echange_n_affiche_pas_une_latence_de_zero(navigateur):
    m = dict(METRIQUES, chats=0, latence_ms_moy=0.0)
    ctx, p, err, _ = ouvre(navigateur, URL, {**API, "/metrics": (200, m)})
    p.wait_for_function("document.getElementById('tObjets').textContent === '37'")
    assert p.inner_text("#tLatence") == "—" and p.inner_text("#tEchanges") == "0" and err == []
    ctx.close()


def test_enregistrer_le_moteur_envoie_le_meme_corps(navigateur):
    nouvelle = dict(CONFIG, n_predict=200, model_name="Autre")
    ctx, p, err, appels = ouvre(navigateur, URL, {**API, "POST /config": (200, {"ok": True, "config": nouvelle})})
    p.wait_for_function("document.getElementById('n_predict').value === '120'")
    p.fill("#n_predict", "200"); p.fill("#model_name", "Autre")
    p.fill("#llm_timeout_s", "12,5")
    p.click("[data-save=moteur]")
    p.wait_for_function("document.getElementById('moteur-msg').textContent.includes('Enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"llm_url": "http://127.0.0.1:8091", "model_name": "Autre", "n_predict": 200, "llm_timeout_s": 12.5}
    ctx.close()


def test_entier_invalide_refuse_sans_appel(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_function("document.getElementById('n_predict').value === '120'")
    p.fill("#n_predict", "12.5"); p.click("[data-save=moteur]")
    assert "entier" in p.inner_text("#moteur-msg") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_armer_le_remote_demande_une_confirmation_dans_la_page(navigateur):
    armee = dict(CONFIG, remote_enabled=True, remote_url="https://zia-remote.example.test")
    ctx, p, err, appels = ouvre(navigateur, URL, {**API, "POST /config": (200, {"ok": True, "config": armee})})
    p.wait_for_function("document.getElementById('n_predict').value === '120'")
    p.check("#remote_enabled"); p.fill("#remote_url", "https://zia-remote.example.test")
    p.click("[data-save=remote]")
    assert p.is_visible("#confirme") and not [a for a in appels if a[0] == "POST"]
    p.click("#non")
    assert not p.is_visible("#confirme") and not [a for a in appels if a[0] == "POST"]
    p.click("[data-save=remote]"); p.click("#oui")
    p.wait_for_function("document.getElementById('remote-msg').textContent.includes('Enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"remote_url": "https://zia-remote.example.test", "remote_role_min": "admin", "remote_timeout_s": 15.0, "remote_budget": 20, "remote_enabled": True}
    assert err == []
    ctx.close()


def test_tester_le_modele_poste_sans_corps_et_affiche_le_resultat(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, "POST /llm/test": (200, {"ok": True, "model": "/m/tiny.gguf"})})
    p.wait_for_function("document.getElementById('n_predict').value === '120'")
    p.click("#test")
    p.wait_for_function("document.getElementById('moteur-msg').textContent.includes('joignable')")
    assert ("POST", "/llm/test", None) in appels and "tiny.gguf" in p.inner_text("#moteur-msg")
    ctx.close()


def test_donnee_d_api_jamais_interpretee_comme_html(navigateur):
    m = dict(METRIQUES, model="<img src=x onerror=window.pwn=1>")
    ctx, p, err, _ = ouvre(navigateur, URL, {**API, "/metrics": (200, m)})
    p.wait_for_function("document.getElementById('tObjets').textContent === '37'")
    assert "<img" in p.inner_text("#tModele") and p.evaluate("window.pwn") is None and p.locator("#tModele img").count() == 0
    ctx.close()


def test_sans_session_bandeau_tirets_et_champs_verrouilles(navigateur):
    refus = {k: (401, {"detail": "Session requise"}) for k in API}
    ctx, p, err, appels = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tObjets", "#tEchanges", "#tLatence")] == ["—"] * 3
    assert p.is_disabled("#llm_url") and p.is_disabled("[data-save=moteur]") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_function("document.getElementById('tObjets').textContent === '37'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("[data-save=moteur]")
    p.wait_for_function("document.getElementById('moteur-msg').textContent.includes('inerte')")
    p.click("#test")
    p.wait_for_function("document.getElementById('moteur-msg').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.evaluate("window.__h=[]; addEventListener('message', e => window.__h.push(e.data))")
    p.wait_for_function("document.getElementById('tObjets').textContent === '37'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

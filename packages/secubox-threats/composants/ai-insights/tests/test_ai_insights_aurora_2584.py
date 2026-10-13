# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /ai-insights/ au profil Aurora : contrôles statiques + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "ai-insights" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for ancien in ("/shared/crt-engine.js", "hybrid-dark", "crt-light", "fonts.googleapis"):
        assert ancien not in SRC
    code = re.sub(r"//[^\n]*", "", SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "onclick="):
        assert interdit not in code, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'ai-insights'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "100vh" not in SRC


def test_routes_lues_et_ecritures_a_l_identique():
    for r in ("/status", "/threats?limit=5", "/threats/history?days=7", "/stats", "/threats?limit=50", "/anomalies?limit=50",
              "/models", "/correlations?limit=20", "/integrations", "/config"):
        assert r in SRC, r
    # exactement les trois écritures de l'ancienne page, mêmes routes, mêmes corps
    assert re.findall(r"ecrire\('POST', '([^']+)'", SRC) == ["/config", "/model/train", "/model/deploy"]
    assert "ecrire('POST', '/model/train', { name, model_type: f.type.value })" in SRC
    assert "ecrire('POST', '/model/deploy', { model_id: id })" in SRC
    for cle in ("detection_threshold", "anomaly_sensitivity", "train_interval_hours", "retention_days", "auto_train"):
        assert cle in SRC
    assert "DELETE" not in SRC and "PUT" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def iso(s):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - s))


JOUR = time.strftime("%Y-%m-%d")
STATUS = {"threats_today": 14, "threats_last_hour": 3, "critical_threats": 2, "active_anomalies": 5, "correlations": 4, "models_deployed": 2}
THREATS = {"threats": [
    {"id": "1", "timestamp": iso(60), "type": "intrusion", "severity": "critical", "source_ip": "203.0.113.9", "target_ip": "192.0.2.10", "score": 93.4,
     "description": "<img src=x onerror=window.__xss=1>Tentative SSH"},
    {"id": "2", "timestamp": iso(600), "type": "scan", "severity": "low", "source_ip": "198.51.100.7", "target_ip": None, "score": 20, "description": "Balayage"}], "total": 2}
HISTORY = {"history": [{"date": JOUR, "total": 10, "critical": 2, "high": 3, "medium": 4, "low": 1}], "period_days": 7, "total_threats": 10}
STATS = {"threats": {"total": 200, "last_hour": 3, "last_24h": 14, "last_week": 39},
         "distributions": {"severity": {"critical": 9, "high": 48, "medium": 81, "low": 62}, "type": {"scan": 150, "c2": 50}}}
ANOM = {"anomalies": [{"id": "a", "timestamp": iso(100), "category": "trafic", "score": 81.2, "baseline_deviation": 2.35, "source": "netflow", "description": "Pic sortant"}], "total": 5}
MODELS = {"models": [
    {"id": "m-ready", "name": "Classificateur", "type": "classification", "version": "1.0.0", "status": "ready", "accuracy": 0.88, "created_at": iso(9999), "deployed_at": None},
    {"id": "m-dep", "name": "Détecteur", "type": "anomaly", "version": "1.0.0", "status": "deployed", "accuracy": 0.0, "created_at": iso(9999), "deployed_at": iso(500)},
    {"id": "m-new", "name": "Essai", "type": "anomaly", "version": "1.0.0", "status": "pending", "accuracy": None, "created_at": iso(9), "deployed_at": None}], "total": 3, "deployed": 2}
CORR = {"correlations": [{"id": "c", "timestamp": iso(300), "alerts": [{}, {}], "correlation_score": 60, "attack_stage": "Intrusion", "ttps": ["T1110"], "recommendation": "Bannir la source"}], "total": 1}
INTEG = {"integrations": [{"name": "nDPId", "enabled": True, "status": "active", "description": "DPI"}]}
CFG = {"detection_threshold": 0.0, "anomaly_sensitivity": 0.8, "train_interval_hours": 12, "retention_days": 30, "auto_train": False, "max_correlations": 100}
API = {"/status": (200, STATUS), "/threats": (200, THREATS), "/threats/history": (200, HISTORY), "/stats": (200, STATS), "/anomalies": (200, ANOM),
       "/models": (200, MODELS), "/correlations": (200, CORR), "/integrations": (200, INTEG), "/config": (200, CFG)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ai-insights":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/ai-insights", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method != "GET":
            statut, corps = routes.get(("POST", chemin), (200, {"status": "ok"}))
        else:
            statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/ai-insights/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/ai-insights/"


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API, jeton="jeton-test")
    p.wait_for_selector("#bDern tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tJour", "#tCrit", "#tHeure", "#tAnom", "#tCorr", "#tMod")] == ["14", "2", "3", "5", "4", "2"]
    assert p.inner_text("#etat") == "EN LIGNE"
    assert "203.0.113.9" in p.inner_text("#bDern") and "CRITIQUE" in p.inner_text("#bDern") and "93" in p.inner_text("#bDern")
    # les données d'API ne sont jamais interprétées comme du HTML
    assert p.evaluate("window.__xss") is None and p.locator("#bMen img").count() == 0
    assert "<img" in p.inner_text("#bMen")
    # cible absente = « — », pas « null » ni « - »
    assert "null" not in p.inner_text("#bMen")
    p.click("#o-anomalies")
    assert "Pic sortant" in p.inner_text("#bAnom") and "235.0 %" in p.inner_text("#bAnom")
    p.click("#o-correl")
    assert "Bannir la source" in p.inner_text("#lCorr") and "T1110" in p.inner_text("#lCorr") and "2 alerte" in p.inner_text("#lCorr")
    p.click("#o-reglages")
    assert "ACTIVE" in p.inner_text("#bInt")                                   # « active » est sain (l'ancienne page l'affichait en orange)
    assert p.locator("#bInt .pill.ok").count() == 1
    # graphique : une barre empilée, graduations réelles (0, 5, 10)
    assert p.locator("#gHisto rect").count() == 4
    assert [t for t in p.locator("#gHisto text").all_text_contents() if t.isdigit()] == ["0", "5", "10"]
    assert all(a[3] == "Bearer jeton-test" for a in appels)
    assert err == []
    ctx.close()


def test_modeles_precision_zero_est_une_mesure(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, API)
    p.click("#o-modeles"); p.wait_for_selector("#bMod tr td")
    lignes = p.locator("#bMod tr")
    assert "0.0 %" in lignes.nth(1).inner_text() and "88.0 %" in lignes.nth(0).inner_text()
    assert lignes.nth(2).locator("td").nth(3).inner_text() == "—"
    ctx.close()


def test_deploiement_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, ("POST", "/model/deploy"): (200, {"status": "deployed", "model": {}})})
    p.click("#o-modeles"); p.wait_for_selector("#bMod tr td.act button")
    p.locator("#bMod tr").first.get_by_text("Déployer").click()
    assert not [a for a in appels if a[0] == "POST"]
    p.locator("#bMod tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rMod').textContent.includes('déployé')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/model/deploy" and json.loads(post[2]) == {"model_id": "m-ready"}
    ctx.close()


def test_entrainement_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, ("POST", "/model/train"): (200, {"status": "training_started", "model": {}})})
    p.click("#o-modeles"); p.click("#addMod")
    p.fill("#fMod [name=name]", "  Mon modèle "); p.select_option("#fMod [name=type]", "classification"); p.click("#fMod button[type=submit]")
    p.wait_for_function("document.getElementById('rMod').textContent.includes('Entraînement lancé')")
    post = [a for a in appels if a[1] == "/model/train"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"name": "Mon modèle", "model_type": "classification"}
    ctx.close()


def test_configuration_lue_sans_defaut_trompeur_et_enregistree(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.click("#o-reglages")
    p.wait_for_function("document.querySelector('#fCfg [name=train_interval_hours]').value === '12'")
    assert p.input_value("#fCfg [name=detection_threshold]") == "0"           # 0 est une valeur, pas « absent »
    assert not p.is_checked("#fCfg [name=auto_train]")
    p.fill("#fCfg [name=retention_days]", "45"); p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rCfg').textContent.includes('enregistrée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"detection_threshold": 0.0, "anomaly_sensitivity": 0.8, "train_interval_hours": 12, "retention_days": 45, "auto_train": False}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tJour", "#tCrit", "#tHeure", "#tAnom", "#tCorr", "#tMod")] == ["—"] * 6
    assert "/login.html?redirect" not in p.url and err == []                  # plus de redirection brutale
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#bDern tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-modeles"); p.locator("#bMod tr").nth(1).get_by_text("Déployer").click(); p.locator("#bMod tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rMod').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


@pytest.mark.parametrize("largeur", [420, 1400])
def test_pas_de_debordement_et_hauteur_annoncee(navigateur, largeur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": largeur, "height": 800})
    p.add_init_script("window.__h=[];addEventListener('message',e=>__h.push(e.data))")
    p.wait_for_selector("#bDern tr td.mono", state="attached")
    for t in ("menaces", "anomalies", "modeles", "correl", "reglages", "bord"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

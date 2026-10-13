# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /sentinelle/ au profil Aurora : test statique + vrai navigateur, API simulée.

Données factices uniquement : réseau de test 001-01 (UIT), IMSI 001010123456789, fréquences de démonstration.
"""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "sentinelle" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert re.findall(r'<link[^>]+href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    for ancien in ("hybrid-dark", "fonts.googleapis", "sentinelle.js", "sentinelle.css", "EventSource"):
        assert ancien not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'sentinelle'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique_de_l_ancienne_page():
    attendu = [
        ("POST", "/trusted"), ("DELETE", "/trusted/"), ("POST", "/alerts/test"), ("POST", "/scan/start"), ("POST", "/scan/stop"),
        ("POST", "/baseline/learn"), ("POST", "/scoring/thresholds"), ("POST", "/rds/start"), ("POST", "/rds/stop"),
        ("POST", "/rds/sweep'"), ("POST", "/rds/sweep/jobs/"),
    ]
    for methode, route in attendu:
        assert re.search(r"ecrire\('%s', '%s" % (methode, re.escape(route)), SRC), (methode, route)
    assert len(re.findall(r"ecrire\('(?:POST|DELETE|PUT|PATCH)'", SRC)) == len(attendu)
    assert "sweep_seconds: 300" in SRC and "'/mode'" not in SRC and "/scan/auto" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
ALERTES = {"alerts": [
    {"id": 2, "ts": NOW - 60, "cell_id": "001-01-100-4021", "arfcn": 976, "score": 82, "reason": "cipher_downgrade", "trusted_label": "Téléphone démo"},
    {"id": 1, "ts": NOW - 4000, "cell_id": "001-01-200-1177", "arfcn": 20, "score": 35, "reason": "operator-test", "trusted_label": None}]}
TRUSTED = {"phones": [{"id": "a1b2c3d4e5f6a7b8", "imsi_hash": "h", "label": "Poste de test", "added_at": NOW - 86400}]}
SCAN = {"running": False, "pid": None, "freq": None, "started_at": None, "stderr_tail": ""}
RDS = {"running": False, "pid": None, "freq": None, "started_at": None, "last_pi": "F201", "last_ps": "RADIODEM", "frames": 12, "stderr_tail": ""}
OBS = {"sightings": [{"cell_id": "001-01-100-4021", "arfcn": 976, "mcc": 1, "mnc": 1, "lac": 100, "ci": 4021, "first_seen": NOW - 9000, "last_seen": NOW - 30, "sighting_count": 7}]}
BASE = {"cells": [{"cell_id": "001-01-100-4021", "mcc": 1, "mnc": 1, "lac": 100, "arfcn": 976, "learn_count": 3, "first_learned": NOW - 9, "last_learned": NOW - 9, "cipher_a5": 3}]}
SEUILS = {"thresholds": {"cipher_downgrade": {"enabled": True, "score": 40}, "relocalization_storm": {"enabled": True, "score": 25, "window_s": 60, "lac_threshold": 3}}}
STATIONS = {"stations": [{"pi": "F201", "ps": "RADIODEM", "rt": "Texte fictif", "pty": 10, "tp": 1, "ta": 0, "freq": "100.6M", "count": 12, "first_seen": NOW - 99, "last_seen": NOW - 20}], "count": 1}
API = {"/alerts": (200, ALERTES), "/trusted": (200, TRUSTED), "/scan/status": (200, SCAN), "/rds/status": (200, RDS), "/rds/sweep/jobs": (200, {"jobs": []}),
       "/observations": (200, OBS), "/baseline": (200, BASE), "/scoring/thresholds": (200, SEUILS), "/rds/stations": (200, STATIONS)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "sentinelle":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/sensor/gsm", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/sensor/gsm/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api_avec_le_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", API, jeton="jeton-factice")
    p.wait_for_selector("#bAlertes tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tAlertes", "#tScore", "#tTel", "#tGsm", "#tRds")] == ["2", "82", "1", "ARRÊTÉ", "ARRÊTÉ"]
    assert "001-01-100-4021" in p.inner_text("#bAlertes") and "Téléphone démo" in p.inner_text("#bAlertes") and "976" in p.inner_text("#bAlertes")
    assert p.inner_text("#etat") == "ALERTE ÉLEVÉE RÉCENTE"
    # lectures protégées : le jeton est bien envoyé (l'ancienne page n'en envoyait aucun)
    assert appels and all(a[3] == "Bearer jeton-factice" for a in appels)
    p.click("#o-tel")
    assert "a1b2c3d4" in p.inner_text("#bTel") and "a1b2c3d4e5f6" not in p.inner_text("#bTel") and "Poste de test" in p.inner_text("#bTel")
    p.click("#o-gsm"); p.wait_for_selector("#bObs td.mono", state="attached")
    assert "001-01-100-4021" in p.inner_text("#bObs") and "7" in p.inner_text("#bObs")
    p.click("#o-fm"); p.wait_for_selector("#bSta td.mono", state="attached")
    assert "RADIODEM" in p.inner_text("#bSta") and "TP" in p.inner_text("#bSta")
    p.click("#o-ref"); p.wait_for_selector("#bRef td.mono", state="attached"); p.wait_for_selector("#seuils .seuil")
    assert "001-01-100-4021" in p.inner_text("#bRef") and "cipher_downgrade" in p.inner_text("#seuils")
    assert err == []
    ctx.close()


def test_ajouter_un_telephone_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", API)
    p.click("#o-tel"); p.click("#addTel")
    p.fill("#fTel [name=imsi]", "001010123456789"); p.fill("#fTel [name=label]", "Poste factice")
    p.click("#fTel button[type=submit]")
    p.wait_for_function("document.getElementById('rTel').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/trusted"][0]
    assert json.loads(post[2]) == {"imsi": "001010123456789", "label": "Poste factice"}
    ctx.close()


def test_supprimer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", {**API, "/trusted/a1b2c3d4e5f6a7b8": (200, {"ok": True})})
    p.click("#o-tel"); p.wait_for_selector("#bTel td.act")
    p.locator("#bTel").get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"] and p.is_visible("#cTel")
    p.locator("#cTel").get_by_text("Annuler").click()
    assert not p.is_visible("#cTel") and not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bTel").get_by_text("Supprimer").click(); p.locator("#cTel").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTel').textContent.includes('retiré')")
    assert ("DELETE", "/trusted/a1b2c3d4e5f6a7b8") in [a[:2] for a in appels]
    ctx.close()


def test_balayage_gsm_demarrage_et_arret_confirme(navigateur):
    en_cours = {"running": True, "pid": 4242, "freq": "925.4M", "started_at": NOW - 5, "stderr_tail": "ok"}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", API)
    p.click("#o-gsm"); p.fill("#fGsm [name=freq]", "925.4M"); p.click("#gsmStart")
    p.wait_for_function("document.getElementById('rGsm').textContent.includes('démarré')")
    assert json.loads([a for a in appels if a[1] == "/scan/start"][0][2]) == {"freq": "925.4M"}
    ctx.close()
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", {**API, "/scan/status": (200, en_cours)})
    p.click("#o-gsm"); p.wait_for_function("document.getElementById('kGEtat').textContent === 'En cours'")
    assert p.inner_text("#tGsm") == "EN COURS" and p.text_content("#gsmErr") == "ok"
    p.click("#gsmStop")
    assert not [a for a in appels if a[1] == "/scan/stop"]
    p.locator("#cGsmC").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rGsm').textContent.includes('arrêté')")
    assert json.loads([a for a in appels if a[1] == "/scan/stop"][0][2]) == {}
    ctx.close()


def test_rds_demarrage_avec_options_et_apprentissage_confirme(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", API)
    p.click("#o-fm"); p.fill("#fFm [name=freq]", "100.6M"); p.fill("#fFm [name=ppm]", "50"); p.fill("#fFm [name=gain]", "28.5"); p.click("#fmStart")
    p.wait_for_function("document.getElementById('rFm').textContent.includes('démarrée')")
    assert json.loads([a for a in appels if a[1] == "/rds/start"][0][2]) == {"freq": "100.6M", "ppm": 50, "gain": 28.5}
    p.click("#fmSweep")
    p.wait_for_function("document.getElementById('rFm').textContent.includes('lancé')")
    assert json.loads([a for a in appels if a[1] == "/rds/sweep"][0][2]) == {}
    p.click("#o-ref"); p.click("#apprend")
    assert not [a for a in appels if a[1] == "/baseline/learn"]
    p.locator("#cRef").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRef').textContent.includes('armé')")
    assert json.loads([a for a in appels if a[1] == "/baseline/learn"][0][2]) == {"sweep_seconds": 300}
    ctx.close()


def test_scores_envoyes_en_entier_apres_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", {**API, "/scoring/thresholds": (200, SEUILS)})
    p.click("#o-ref"); p.wait_for_selector("#seuils .seuil")
    p.locator("#seuils input[type=number]").first.fill("55"); p.locator("#seuils input[type=number]").first.dispatch_event("change")
    p.click("#appliquer")
    assert not [a for a in appels if a[0] == "POST" and a[1] == "/scoring/thresholds"]
    p.locator("#cSeuils").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSeuils').textContent.includes('appliqués')")
    corps = json.loads([a for a in appels if a[0] == "POST" and a[1] == "/scoring/thresholds"][0][2])
    # le score édité change ; les paramètres propres à l'heuristique (window_s…) repartent intacts
    assert corps["cipher_downgrade"]["score"] == 55 and corps["relocalization_storm"] == {"enabled": True, "score": 25, "window_s": 60, "lac_threshold": 3}
    ctx.close()


def test_alerte_de_test(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/sentinelle/", {**API, "/alerts/test": (200, {"ok": True, "id": 9})})
    p.wait_for_selector("#bAlertes td.mono", state="attached"); p.click("#testAlerte")
    p.wait_for_function("document.getElementById('rAlertes').textContent.includes('id 9')")
    assert json.loads([a for a in appels if a[1] == "/alerts/test"][0][2]) == {}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/sentinelle/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tAlertes", "#tScore", "#tDerniere", "#tTel", "#tGsm", "#tRds")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/sentinelle/?demo=1", {})
    p.wait_for_selector("#bAlertes td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#testAlerte")
    p.wait_for_function("document.getElementById('rAlertes').textContent.includes('inerte')")
    p.click("#o-tel"); p.locator("#bTel").get_by_text("Supprimer").first.click(); p.locator("#cTel").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTel').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/sentinelle/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bAlertes tr td.mono", state="attached")
    for o in ("alertes", "tel", "gsm", "fm", "ref"):
        p.click("#o-" + o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), o
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

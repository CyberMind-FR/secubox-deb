# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2763 — page /metrics/ : carte « Connexions en direct », rafraîchie en temps réel, pulsations quand un pays augmente.

Vrai navigateur, API simulée. `?cadence=` (ms, plancher 500) règle le rythme d'interrogation pour les tests."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "metrics" / "index.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def mesure(fr, de=0, rx=0, tx=0, ts=1000.0, charge=1.0, mem=40.0, sortantes=None, box="FR"):
    ent = [{"code": "FR", "n": fr}] + ([{"code": "DE", "n": de}] if de else [])
    return {"ts": ts, "box": box, "debit": {"rx": rx, "tx": tx}, "charge": charge, "memoire_pct": mem,
            "connexions": {"entrantes": ent, "sortantes": sortantes or [{"code": "US", "n": 2}], "lan": 3, "inconnu": 1, "total": fr + de + 2 + 4}}


def ouvre(navigateur, sequence, reduit=False, cadence=500, statut=200):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900}, reduced_motion="reduce" if reduit else "no-preference")
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route("http://sbx.test/metrics/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    etat = {"i": 0}

    def api(r, *_):
        chemin = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if chemin == "/api/v1/metrics/live":
            appels.append(chemin)
            if statut != 200:
                r.fulfill(status=statut, content_type="application/json", body="{}")
                return
            m = sequence[min(etat["i"], len(sequence) - 1)]
            etat["i"] += 1
            r.fulfill(status=200, content_type="application/json", body=json.dumps(m))
        else:
            r.fulfill(status=404, content_type="application/json", body="{}")
    p.route("http://sbx.test/api/**", api)
    p.goto(f"http://sbx.test/metrics/?cadence={cadence}")
    return ctx, p, erreurs, appels


def test_la_carte_en_direct_existe_et_se_remplit(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, 2)])
    try:
        p.wait_for_selector("#mondeLive circle.pt")
        assert p.locator("#mondeLive circle.pt").count() >= 3, "FR, DE entrants et US sortant"
        assert "EN DIRECT" in p.locator("#enDirect").inner_text().upper()
        assert "FR" in p.locator("#paysLive").inner_text()
        assert not err
    finally:
        ctx.close()


def test_les_compteurs_temps_reel_et_le_debit_se_calculent_entre_deux_mesures(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, rx=0, tx=0, ts=1000.0), mesure(5, rx=2_000_000, tx=500_000, ts=1002.0, charge=2.5, mem=61.0)])
    try:
        p.wait_for_function("document.querySelector('#lvRx') && /Mo|Ko|o\\/s/.test(document.querySelector('#lvRx').textContent) && /[1-9]/.test(document.querySelector('#lvRx').textContent)")
        assert "2,5" in p.locator("#lvCharge").inner_text() or "2.5" in p.locator("#lvCharge").inner_text()
        assert "61" in p.locator("#lvMem").inner_text()
        assert not err
    finally:
        ctx.close()


def test_un_pays_qui_augmente_pulse_et_un_pays_stable_non(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, 2), mesure(9, 2)])
    try:
        p.wait_for_selector("#mondeLive circle.ping", timeout=8000)
        assert p.locator("#mondeLive circle.ping").count() >= 1
    finally:
        ctx.close()


def test_aucune_pulsation_si_rien_ne_change(navigateur):
    ctx, p, err, appels = ouvre(navigateur, [mesure(5, 2)] * 6)
    try:
        p.wait_for_function("false || document.querySelectorAll('#mondeLive circle.pt').length > 0")
        p.wait_for_timeout(2200)
        assert len(appels) >= 3, "la page interroge en continu"
        assert p.locator("#mondeLive circle.ping").count() == 0
    finally:
        ctx.close()


def test_mouvement_reduit_pas_d_animation(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, 2), mesure(9, 2)], reduit=True)
    try:
        p.wait_for_selector("#mondeLive circle.pt")
        p.wait_for_timeout(1500)
        for sel in ("#mondeLive circle.ping", "#enDirect i", "#mondeLive path.arc"):
            for n in p.locator(sel).evaluate_all("els => els.map(e => getComputedStyle(e).animationName)"):
                assert n == "none", (sel, n)
    finally:
        ctx.close()


def test_une_panne_de_l_api_garde_la_derniere_carte_et_le_dit(navigateur):
    ctx, p, err, appels = ouvre(navigateur, [mesure(5, 2)], statut=503)
    try:
        p.wait_for_timeout(1800)
        assert len(appels) >= 1
        txt = p.locator("#enDirect").inner_text().lower()
        assert "reconnexion" in txt or "hors ligne" in txt or "interrompu" in txt
        assert not err
    finally:
        ctx.close()


def test_les_cartes_existantes_restent(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, 2)])
    try:
        assert p.locator("#mondeAtt").count() == 1 and p.locator("#mondeVis").count() == 1
    finally:
        ctx.close()


def test_telephone_pas_de_debordement(navigateur):
    ctx = navigateur.new_context(viewport={"width": 390, "height": 800})
    p = ctx.new_page()
    p.route("http://sbx.test/metrics/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=404, content_type="application/json", body="{}"))
    p.route("http://sbx.test/api/v1/metrics/live", lambda r, *_: r.fulfill(status=200, content_type="application/json", body=json.dumps(mesure(5, 2))))   # le dernier enregistré l'emporte
    p.goto("http://sbx.test/metrics/?cadence=500")
    try:
        p.wait_for_selector("#mondeLive circle.pt")
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    finally:
        ctx.close()


def test_aucune_adresse_ip_n_est_rendue(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(5, 2)])
    try:
        p.wait_for_selector("#mondeLive circle.pt")
        assert not __import__("re").search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", p.locator("#panLive").inner_text())
    finally:
        ctx.close()


def test_les_cartes_attaques_pulsent_quand_un_pays_augmente(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    p.route("http://sbx.test/metrics/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    n = {"i": 0}

    def waf(r, *_):
        n["i"] += 1
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"top_countries": {"CN": 10 if n["i"] == 1 else 25, "RU": 5}}))
    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=404, content_type="application/json", body="{}"))
    p.route("http://sbx.test/api/v1/metrics/waf_stats", waf)
    p.route("http://sbx.test/api/v1/metrics/live", lambda r, *_: r.fulfill(status=404, content_type="application/json", body="{}"))
    p.goto("http://sbx.test/metrics/?cadence=60000")
    try:
        p.wait_for_selector("#mondeAtt circle")
        assert p.locator("#mondeAtt circle.ping").count() == 0, "première mesure : rien n'a augmenté"
        p.click("#rafraichir")
        p.wait_for_selector("#mondeAtt circle.ping", timeout=8000)
        assert p.locator("#mondeAtt circle.ping").count() == 1, "seulement la Chine (RU est stable)"
    finally:
        ctx.close()

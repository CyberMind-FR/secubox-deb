# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2767 — « Système en direct » (/glances/direct.html), à côté de la page Glances : jauges, cœurs, courbes, processus qui glissent, en temps réel.

Vrai navigateur, API simulée. `?cadence=` (ms, plancher 300) règle le rythme pour les tests."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "glances" / "direct.html"
SRC = PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def mesure(ts=100.0, cpu=(20.0, 40.0, 60.0, 80.0), mem=50.0, rx=0, tx=0, charge=(1.0, 0.8, 0.5), procs=None, swap=(10.0, 100, 1000)):
    return {"ts": ts, "cpu": {"total": sum(cpu) / len(cpu), "coeurs": list(cpu), "nb": len(cpu)},
            "memoire": {"pct": mem, "utilise": 4 * 2**30, "total": 8 * 2**30, "dispo": 4 * 2**30},
            "swap": {"pct": swap[0], "utilise": swap[1], "total": swap[2]},
            "disques": [{"point": "/", "pct": 61.0, "utilise": 3 * 2**30, "total": 5 * 2**30}],
            "reseau": {"interfaces": [], "total": {"rx": rx, "tx": tx}}, "temperatures": [{"nom": "cpu_thermal", "c": 51.5}],
            "charge": list(charge), "uptime_s": 93784,
            "processus": procs if procs is not None else [{"pid": 10, "nom": "sbxwaf", "cpu": 12.0, "memoire": 2**25}, {"pid": 20, "nom": "nginx", "cpu": 3.0, "memoire": 2**24}]}


def ouvre(navigateur, sequence, statut=200, cadence=300, taille=None, reduit=False):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900}, reduced_motion="reduce" if reduit else "no-preference")
    p = ctx.new_page()
    err, appels = [], []
    p.on("pageerror", lambda e: err.append(str(e)))
    p.route("http://sbx.test/glances/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    n = {"i": 0}

    def api(r, *_):
        appels.append(r.request.url)
        if statut != 200:
            r.fulfill(status=statut, content_type="application/json", body="{}")
            return
        m = sequence[min(n["i"], len(sequence) - 1)]
        n["i"] += 1
        r.fulfill(status=200, content_type="application/json", body=json.dumps(m))
    p.route("http://sbx.test/api/v1/metrics/systeme", api)
    p.goto(f"http://sbx.test/glances/direct.html?cadence={cadence}")
    return ctx, p, err, appels


def test_les_jauges_et_tuiles_se_remplissent(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure()])
    try:
        p.wait_for_function("document.querySelector('#tCpu').textContent.includes('50')")
        assert "50,0 %" in p.inner_text("#tCpu") and "50,0 %" in p.inner_text("#tMem")
        assert "4,0 Go / 8,0 Go" in p.inner_text("#sMem")
        assert p.inner_text("#tLoad") == "1,00" and "0,80" in p.inner_text("#sLoad")
        assert "1 j 2 h" in p.inner_text("#tUp")
        assert p.locator("#etat").inner_text().upper().startswith("EN DIRECT")
        assert not err
    finally:
        ctx.close()


def test_chaque_coeur_a_sa_barre(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(cpu=(10.0, 30.0, 50.0, 70.0, 90.0, 95.0))])
    try:
        p.wait_for_selector("#coeurs .coeur")
        assert p.locator("#coeurs .coeur").count() == 6 and "6 cœurs" in p.inner_text("#nCoeurs")
        assert p.locator("#coeurs .coeur").nth(5).evaluate("e => e.firstChild.style.height") == "95%"
    finally:
        ctx.close()


def test_le_debit_se_calcule_entre_deux_mesures(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(ts=100.0, rx=0, tx=0), mesure(ts=102.0, rx=4 * 2**20, tx=2**20)])
    try:
        p.wait_for_function("/Mo|Ko/.test(document.querySelector('#tRx').textContent)")
        assert "2,0 Mo/s" in p.inner_text("#tRx") and "512 Ko/s" in p.inner_text("#tTx")
    finally:
        ctx.close()


def test_les_courbes_grandissent_a_chaque_mesure(navigateur):
    seq = [mesure(ts=100.0 + 2 * i, cpu=(10.0 + 5 * i,) * 4, rx=i * 2**20, tx=i * 2**18) for i in range(8)]
    ctx, p, err, _ = ouvre(navigateur, seq)
    try:
        p.wait_for_function("document.querySelectorAll('#gCpu polyline').length === 1 && document.querySelector('#gCpu polyline').getAttribute('points').split(' ').length >= 5")
        assert p.locator("#gNet polyline").count() == 2
        assert not err
    finally:
        ctx.close()


def test_le_survol_d_une_courbe_lit_la_valeur_a_cet_instant(navigateur):
    seq = [mesure(ts=100.0 + 2 * i, cpu=(10.0 + 5 * i,) * 4) for i in range(8)]
    ctx, p, err, _ = ouvre(navigateur, seq)
    try:
        p.wait_for_function("document.querySelector('#gCpu polyline') && document.querySelector('#gCpu polyline').getAttribute('points').split(' ').length >= 5")
        p.wait_for_timeout(2600)                                  # l'historique est complet : plus de reconstruction pendant le survol
        b = p.locator("#gCpu").bounding_box()
        p.mouse.move(b["x"] + b["width"] * 0.995, b["y"] + b["height"] / 2)
        p.wait_for_function("document.querySelector('#lCpu').textContent.length > 3")
        assert "CPU" in p.inner_text("#lCpu") and "%" in p.inner_text("#lCpu")
    finally:
        ctx.close()


def test_l_humeur_suit_la_charge(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(cpu=(2.0, 3.0, 2.0, 3.0), mem=20.0, charge=(0.1, 0.1, 0.1))])
    try:
        p.wait_for_function("document.querySelector('#mood').textContent.length > 0")
        assert "Zen" in p.inner_text("#mood")
    finally:
        ctx.close()
    ctx, p, err, _ = ouvre(navigateur, [mesure(cpu=(99.0, 98.0, 99.0, 97.0), mem=95.0, charge=(9.0, 8.0, 7.0))])
    try:
        p.wait_for_function("document.querySelector('#mood').textContent.length > 0")
        assert "En feu" in p.inner_text("#mood")
    finally:
        ctx.close()


def test_le_nom_d_un_processus_est_du_texte_jamais_du_html(navigateur):
    procs = [{"pid": 1, "nom": "<img src=x onerror=\"window.__xss=1\">", "cpu": 5.0, "memoire": 2**20}]
    ctx, p, err, _ = ouvre(navigateur, [mesure(procs=procs)])
    try:
        p.wait_for_selector("#bProc tr[data-pid]")
        assert "<img" in p.inner_text("#bProc") and p.evaluate("window.__xss") is None
        assert p.locator("#bProc img").count() == 0
    finally:
        ctx.close()


def test_un_processus_qui_change_de_rang_garde_sa_ligne(navigateur):
    a = [{"pid": 1, "nom": "alpha", "cpu": 30.0, "memoire": 2**20}, {"pid": 2, "nom": "beta", "cpu": 10.0, "memoire": 2**20}]
    b = [{"pid": 2, "nom": "beta", "cpu": 50.0, "memoire": 2**20}, {"pid": 1, "nom": "alpha", "cpu": 30.0, "memoire": 2**20}]
    ctx, p, err, _ = ouvre(navigateur, [mesure(procs=a), mesure(ts=102.0, procs=b)])
    try:
        p.wait_for_function("document.querySelector('#bProc tr').dataset.pid === '2'")
        assert [r.get_attribute("data-pid") for r in p.locator("#bProc tr").all()] == ["2", "1"]
    finally:
        ctx.close()


def test_pause_arrete_les_interrogations_et_reprendre_les_relance(navigateur):
    ctx, p, err, appels = ouvre(navigateur, [mesure()])
    try:
        p.wait_for_selector("#bProc tr[data-pid]")
        p.click("#pause")
        assert "PAUSE" in p.inner_text("#etat").upper()
        n = len(appels)
        p.wait_for_timeout(1200)
        assert len(appels) <= n + 1, "plus d'interrogation en pause"
        n = len(appels)
        p.click("#pause")
        p.wait_for_timeout(1000)
        assert len(appels) > n
    finally:
        ctx.close()


def test_une_panne_dit_reconnexion(navigateur):
    ctx, p, err, appels = ouvre(navigateur, [mesure()], statut=503)
    try:
        p.wait_for_timeout(1000)
        assert "RECONNEXION" in p.inner_text("#etat").upper() and not err
    finally:
        ctx.close()


def test_sans_session_le_bandeau_est_affiche(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure()], statut=401)
    try:
        p.wait_for_function("!document.querySelector('#session').hidden")
        assert "session" in p.inner_text("#session").lower()
    finally:
        ctx.close()


def test_mouvement_reduit_pas_d_animation(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure()], reduit=True)
    try:
        p.wait_for_selector("#coeurs .coeur")
        assert p.locator("#coeurBat").evaluate("e => getComputedStyle(e).animationName") == "none"
        assert p.locator("#etat i").evaluate("e => getComputedStyle(e).animationName") == "none"
    finally:
        ctx.close()


def test_demonstration_animee_sans_api(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    p.route("http://sbx.test/glances/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.goto("http://sbx.test/glances/direct.html?demo=1&cadence=300")
    try:
        p.wait_for_selector("#bProc tr[data-pid]")
        assert not p.locator("#demo").is_hidden()
        a = p.inner_text("#tCpu")
        p.wait_for_function(f"document.querySelector('#tCpu').textContent !== {json.dumps(a)}")
    finally:
        ctx.close()


def test_telephone_pas_de_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, [mesure(cpu=tuple(float(10 * i) for i in range(16)))], taille={"width": 390, "height": 800})
    try:
        p.wait_for_selector("#coeurs .coeur")
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    finally:
        ctx.close()


def test_hygiene_de_la_page_et_lien_vers_glances():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<link[^>]+href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    assert not re.search(r"<script[^>]+src=", SRC) and "fonts.googleapis" not in SRC
    assert "lorem" not in SRC.lower() and "cmdline" not in SRC.lower()
    assert "'POST'" not in SRC, "lecture seule"
    assert "sbx_token" in SRC and "/api/v1/metrics/systeme" in SRC
    assert 'href="/glances/"' in SRC, "retour vers la page Glances actuelle"

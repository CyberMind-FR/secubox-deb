# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#4053 — la fiche d'une appli s'ouvre depuis la Mosaïque, les Applis et les Instances, et paramètre l'appli
(port, veille, démarrage au boot, journaux) par les routes gardées. Vrai navigateur, API simulée."""
import json

import pytest

from test_streamlit_aurora_2653 import BASE, NOW, ecritures, ouvre

playwright = pytest.importorskip("playwright.sync_api")

FICHE = {"name": "alpha", "state": "sleeping", "running": False, "entrypoint": "app.py", "port": 0, "port_declare": 8501,
         "last_active": NOW - 600, "sleep_after_seconds": 900, "veille": True, "veille_minutes": 0, "autostart": True,
         "veille_commune_minutes": 15, "publications": [], "domaine_retire": "alpha.example.org",
         "depubliee": "2026-10-29T03:30:17Z", "issues": []}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def test_fiche_depuis_la_mosaique_puis_parametrage(navigateur):
    routes = dict(BASE)
    routes["/app/alpha"] = (200, FICHE)
    routes["/app/alpha/logs"] = (200, {"logs": ["ligne un", "ligne deux"]})
    routes["/publications"] = (200, {"domaine": "example.org", "apps": {}})
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=mosaic", routes)
    p.wait_for_selector("button[data-fiche='alpha']")
    p.click("button[data-fiche='alpha']")
    p.wait_for_function("document.getElementById('fCorps').textContent.includes('Veille et démarrage')")
    corps = p.inner_text("#fCorps")
    assert "alpha.example.org retirée" in corps and "8501" in corps
    # Veille : désactivée puis enregistrée.
    p.uncheck("#fCorps label.coche input >> nth=0")
    p.click("#fCorps button:has-text('Enregistrer')")
    p.wait_for_function("document.getElementById('fRetour').textContent.length > 0 && !document.getElementById('fRetour').textContent.endsWith('…')")
    # Port.
    p.fill("#fCorps input[type=number] >> nth=0", "8540")
    p.click("#fCorps button:has-text('Appliquer')")
    p.wait_for_timeout(200)
    # Journaux.
    p.click("#fCorps button:has-text('Charger le journal')")
    p.wait_for_function("document.querySelector('#fCorps pre.journal').textContent.includes('ligne deux')")
    w = {(m, c): json.loads(b) if b else None for m, c, b, _a in ecritures(appels)}
    assert w[("POST", "/app/alpha/veille")] == {"actif": False, "minutes": 0}
    assert w[("POST", "/app/alpha/port")] == {"port": 8540}
    # Fermer.
    p.click("#fFermer")
    assert p.is_hidden("#fiche")
    assert err == []
    ctx.close()


def test_fiche_depuis_les_applis_et_les_instances(navigateur):
    routes = dict(BASE)
    routes["/app/alpha"] = (200, FICHE)
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps button.lienfiche")
    p.click("#bApps button.lienfiche >> text=alpha")
    p.wait_for_function("document.getElementById('fTitre').textContent === 'alpha' && document.getElementById('fCorps').textContent.includes('Publication')")
    p.click("#t-instances")
    p.wait_for_selector("#bInst button.lienfiche")
    assert p.is_visible("#fInst") and p.inner_text("#bInst").count("alpha") >= 1
    assert err == []
    ctx.close()


def test_fiche_en_demonstration_sans_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?demo=1&onglet=mosaic", {})
    p.wait_for_selector("button[data-fiche='tableau-capteurs']")
    p.click("button[data-fiche='tableau-capteurs']")
    p.wait_for_function("document.getElementById('fCorps').textContent.includes('capteurs.example.org')")
    p.click("#fCorps button:has-text('Arrêter')")
    assert appels == [] and err == []
    ctx.close()

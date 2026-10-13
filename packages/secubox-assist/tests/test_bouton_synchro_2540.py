# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2540 — /assist/ : le bouton « Synchroniser » appelle POST /api/v1/annuaire/sync/now et le dit, sans boîte native."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = (Path(__file__).resolve().parents[1] / "www" / "assist" / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, reponse_sync, statut=200):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    appels = []
    p.route("http://sbx.test/", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))

    def api(r, *_):
        if r.request.url.endswith("/annuaire/sync/now"):
            appels.append(r.request.method)
            return r.fulfill(status=statut, content_type="application/json", body=json.dumps(reponse_sync))
        corps = {"active_session": None, "pending": []} if r.request.url.endswith("/sessions") else []
        r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    boites = []
    p.on("dialog", lambda d: (boites.append(d.type), d.dismiss()))
    p.goto("http://sbx.test/")
    return ctx, p, appels, boites


def test_le_bouton_force_une_synchro_et_dit_combien_d_entrees(navigateur):
    ctx, p, appels, boites = ouvre(navigateur, {"ok": True, "resultat": {"peers": 1, "ingested": 2, "errors": 0}})
    p.click("#sync-now")
    p.wait_for_function("document.getElementById('sync-etat').textContent.includes('reçue')")
    assert appels == ["POST"] and "2 entrée(s) reçue(s)" in p.inner_text("#sync-etat") and not p.is_disabled("#sync-now") and boites == []
    ctx.close()


def test_deja_a_jour_et_pair_injoignable(navigateur):
    ctx, p, _, _ = ouvre(navigateur, {"ok": True, "resultat": {"peers": 1, "ingested": 0, "errors": 1}})
    p.click("#sync-now")
    p.wait_for_function("document.getElementById('sync-etat').textContent.includes('à jour')")
    assert "1 pair(s) injoignable(s)" in p.inner_text("#sync-etat")
    ctx.close()


def test_sans_pair_et_sans_session(navigateur):
    ctx, p, _, _ = ouvre(navigateur, {"ok": False, "resultat": None})
    p.click("#sync-now")
    p.wait_for_function("document.getElementById('sync-etat').textContent.includes('Aucun pair')")
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, {"detail": "x"}, statut=401)
    p.click("#sync-now")
    p.wait_for_function("document.getElementById('sync-etat').textContent.includes('Échec')")
    assert "session requise" in p.inner_text("#sync-etat")
    ctx.close()

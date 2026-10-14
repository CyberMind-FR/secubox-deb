# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2649 — /localrecall/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants/localrecall/www/localrecall/index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'localrecall'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC


def test_aucun_secret_ni_stockage():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "localrecall":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/localrecall", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        cle = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, routes.get(cle, (404, {})))
        else:
            statut, corps = routes.get(cle, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/localrecall/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


STATUS = {"module": "localrecall", "status": "ok", "version": "1.0.0", "total_memories": 2}
STATS = {"total_memories": 2, "by_category": {"threats": 1, "general": 1, "decisions": 0}, "top_tags": {"t": 1}, "storage_bytes": 2048}
MEMS = {"memories": [{"id": "m1", "category": "threats", "content": "<i>contenu</i> dangereux", "importance": 8, "tags": ["a", "b"], "source": "src1", "timestamp": "2026-10-14T10:00:00Z"},
                     {"id": "m2", "category": "general", "content": "autre", "importance": 3, "tags": [], "timestamp": "2026-10-13T10:00:00Z"}], "total": 2, "limit": 10, "offset": 0}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/memories?limit=10": (200, MEMS)}
URL = "http://sbx.test/localrecall/"


def test_routes_et_corps_a_l_identique():
    for r in ("'POST', '/search', { query, limit: 10 }", "'DELETE', '/memories/'", "'/ingest'", "fd.append('files', x)", "'/status'", "'/stats'", "'/memories?limit=10'"):
        assert r in SRC


def test_tuiles_et_souvenirs_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lSouv .elt")
    assert [p.inner_text(i) for i in ("#tSouv", "#tCat", "#tStock", "#tReq")] == ["2", "2", "2,0 Ko", "—"]
    t = p.inner_text("#lSouv")
    assert "<i>contenu</i> dangereux" in t and p.locator("#lSouv i").count() == 0 and "Importance 8/10" in t
    assert "threats" in p.inner_text("#lCat") and err == []
    ctx.close()


def test_recherche_envoie_le_meme_corps(navigateur):
    routes = {**API, "/search": (200, {"results": [{"id": "m1", "category": "threats", "content": "trouvé ici", "importance": 8, "tags": ["z"]}], "count": 1})}
    ctx, p, err, appels = ouvre(navigateur, URL, routes)
    p.wait_for_selector("#lSouv .elt")
    p.fill("#q", "menace"); p.press("#q", "Enter")
    p.wait_for_selector("#lRech .elt")
    assert "trouvé ici" in p.inner_text("#lRech") and "1 résultat" in p.inner_text("#nRech")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/search"][0]
    assert json.loads(post[2]) == {"query": "menace", "limit": 10}
    assert err == []
    ctx.close()


def test_suppression_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, "/memories/m1": (200, {"status": "deleted"})})
    p.wait_for_selector("#lSouv .elt")
    p.locator("#lSouv .elt").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#lSouv .elt").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSup').textContent.includes('supprimé')")
    assert ("DELETE", "/memories/m1", None) in appels
    ctx.close()


def test_annuler_ne_supprime_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lSouv .elt")
    p.locator("#lSouv .elt").first.get_by_text("Supprimer").click()
    p.locator("#lSouv .elt").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    ctx.close()


def test_ingestion_envoie_les_fichiers_en_multipart(navigateur, tmp_path):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, "/ingest": (200, {"ingested": 1})})
    p.wait_for_selector("#lSouv .elt")
    f = tmp_path / "note.txt"; f.write_text("bonjour")
    p.set_input_files("#fichiers", str(f)); p.click("#btnIng")
    p.wait_for_function("document.getElementById('rIng').textContent.includes('ingéré')")
    post = [a for a in appels if a[1] == "/ingest"][0]
    assert post[0] == "POST" and "note.txt" in (post[2] or "")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tSouv", "#tCat", "#tStock", "#tReq")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#lSouv .elt")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#lSouv .elt").first.get_by_text("Supprimer").click()
    p.locator("#lSouv .elt").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rSup').textContent.includes('inerte')")
    p.fill("#q", "pare-feu"); p.press("#q", "Enter")
    p.wait_for_selector("#lRech .elt")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#lSouv .elt")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /cloner/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "cloner" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'cloner'" in SRC and "demo" in SRC and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_routes_d_ecriture_a_l_identique():
    assert "ecrire('POST', '/backups', corps)" in SRC
    assert "{ name: f.name.value.trim(), description: f.description.value.trim(), compress: f.compress.checked }" in SRC
    assert "ecrire('DELETE', '/backups/' + encodeURIComponent(id))" in SRC
    assert "'/restore', { backup_id: id }" in SRC
    assert "ecrire('POST', '/cleanup?keep=' + keep)" in SRC
    for lecture in ("'/status'", "'/backups'", "'/backups/' + encodeURIComponent(id)"):
        assert lecture in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"running": False, "last_backup": "b-2.tar.gz", "last_backup_time": "2026-10-13T03:00:00", "last_error": None, "backup_count": 2,
          "total_backup_size": "3.0 MB", "disk": {"total": 1000, "used": 800, "free": 200, "total_human": "1.0 KB", "used_human": "800.0 B", "free_human": "200.0 B", "percent_used": 80.0},
          "schedule": {"enabled": True, "interval": "daily", "retention": 7, "time": "03:00"}}
LISTE = {"backups": [
    {"id": "b-2.tar.gz", "path": "/x/b-2.tar.gz", "size": 2097152, "size_human": "2.0 MB", "created": "2026-10-13T03:00:00", "description": "<b>nuit</b>", "paths": ["/etc/secubox"]},
    {"id": "b-1.tar", "path": "/x/b-1.tar", "size": 1048576, "size_human": "1.0 MB", "created": "2026-10-12T03:00:00", "description": "", "paths": []}]}
DETAIL = {"id": "b-2.tar.gz", "size": 2097152, "created": "2026-10-13T03:00:00", "description": "", "paths": ["/etc/secubox"],
          "contents": [{"name": "etc/secubox/a.toml", "size": 10, "type": "file"}], "contents_truncated": False}
API = {"/status": (200, STATUS), "/backups": (200, LISTE), "/backups/b-2.tar.gz": (200, DETAIL)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, dialogues = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "cloner":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/cloner", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin + ("?" + r.request.url.split("?", 1)[1] if "?" in r.request.url else ""), r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get((r.request.method, chemin), (200, {"status": "ok"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/cloner/**", api)
    p.goto(url)
    p._dialogues = dialogues
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cloner/", API)
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    assert p.inner_text("#tNb") == "2" and p.inner_text("#tTaille").startswith("3") and "Mo" in p.inner_text("#tTaille")
    assert p.inner_text("#tDisque").startswith("80") and "tuile att" in p.get_attribute("#cDisque", "class")
    assert p.inner_text("#etat") == "AU REPOS" and "b-1.tar" in p.inner_text("#bSauv") and "2 Mo" in p.inner_text("#bSauv")
    # la description d'API est du texte, jamais du HTML
    assert "<b>nuit</b>" in p.inner_text("#bSauv") and p.locator("#bSauv b").count() == 0
    assert "chaque jour" in p.inner_text("#kPlan") and err == []
    ctx.close()


def test_jeton_envoye_et_detail(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cloner/", API)
    p.evaluate("localStorage.setItem('sbx_token','jt')")
    p.click("#rafraichir"); p.wait_for_selector("#bSauv tr td.act")
    assert any(a[3] == "Bearer jt" for a in appels)
    p.locator("#bSauv tr").first.get_by_text("Détails").click()
    p.wait_for_function("document.getElementById('xContenu').textContent.includes('a.toml')")
    assert "/etc/secubox" in p.inner_text("#xChemins") and p.is_visible("#pDetail")
    ctx.close()


def test_suppression_demande_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cloner/", API)
    p.wait_for_selector("#bSauv tr td.act")
    p.locator("#bSauv tr").first.get_by_text("Supprimer").click()
    assert p.is_visible("#conf") and "b-2.tar.gz" in p.inner_text("#confMsg")
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('supprimée')")
    assert ("DELETE", "/backups/b-2.tar.gz", None) in [a[:3] for a in appels] and p._dialogues == []
    ctx.close()


def test_restauration_nomme_la_cible_et_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cloner/", API)
    p.wait_for_selector("#bSauv tr td.act")
    p.locator("#bSauv tr").first.get_by_text("Détails").click()
    p.wait_for_selector("#dRestaurer", state="visible")
    p.click("#dRestaurer")
    msg = p.inner_text("#confMsg")
    assert "b-2.tar.gz" in msg and "/ (racine" in msg and "ÉCRASÉS" in msg
    assert not [a for a in appels if a[1].endswith("/restore")]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[1].endswith("/restore")]
    p.click("#dRestaurer"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Restauration terminée')")
    post = [a for a in appels if a[1] == "/backups/b-2.tar.gz/restore"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"backup_id": "b-2.tar.gz"}
    ctx.close()


def test_creation_envoie_le_meme_corps_et_ecrasement_confirme(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cloner/", API)
    p.wait_for_selector("#bSauv tr td.act")
    p.click("#creer"); p.fill("#fCreer [name=name]", "manuelle"); p.fill("#fCreer [name=description]", "essai")
    p.click("#creerOk")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Sauvegarde créée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/backups"][0]
    assert json.loads(post[2]) == {"name": "manuelle", "description": "essai", "compress": True}
    # nom déjà pris : confirmation avant d'écraser
    p.click("#creer"); p.fill("#fCreer [name=name]", "b-1"); p.uncheck("#fCreer [name=compress]"); p.click("#creerOk")
    assert p.is_visible("#conf") and "b-1.tar" in p.inner_text("#confMsg")
    assert len([a for a in appels if a[0] == "POST" and a[1] == "/backups"]) == 1
    ctx.close()


def test_nettoyage_valide_confirme_et_garde_la_meme_route(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/cloner/", {**API, ("POST", "/cleanup"): (200, {"status": "ok", "deleted": 1, "kept": 1})})
    p.wait_for_selector("#bSauv tr td.act")
    p.click("#nettoyer"); p.fill("#fNettoyer [name=keep]", "1"); p.click("#fNettoyer button[type=submit]")
    assert "1 sauvegarde" in p.inner_text("#confMsg") and not [a for a in appels if a[1].startswith("/cleanup")]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('supprimée')")
    assert ("POST", "/cleanup?keep=1") in [a[:2] for a in appels] and p._dialogues == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cloner/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tNb", "#tTaille", "#tDisque", "#tLibre", "#tDerniere")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/cloner/?demo=1", {})
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bSauv tr").first.get_by_text("Supprimer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/cloner/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bSauv tr td.mono", state="attached")
    p.locator("#bSauv tr").first.get_by_text("Détails").click(); p.wait_for_selector("#xContenu li")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

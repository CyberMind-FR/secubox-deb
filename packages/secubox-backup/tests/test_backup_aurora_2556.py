# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /backup/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "backup" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'backup'" in SRC and "demo" in SRC and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    assert "ecrire('/create', { type, encrypt })" in SRC
    assert "ecrire('/container/backup', { name, encrypt })" in SRC
    assert "ecrire('/cleanup')" in SRC
    assert "method: 'POST'" in SRC and "DELETE" not in SRC
    for lecture in ("'/status'", "'/list?type=all'", "'/containers'", "'/encryption'"):
        assert lecture in SRC
    assert 'id="chiffrer" checked' in SRC            # chiffrement coché par défaut (#1903)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"storage_path": "/srv/backups", "storage_used": "2.4G", "last_backup": {"config": NOW - 3600, "containers": 0, "services": 0}, "container_count": 2}
LISTE = {"backups": [
    {"file": "config-1.tar.gz.age", "type": "config", "size": "1.2M", "timestamp": NOW - 3600, "encrypted": True},
    {"file": "web-1.tar.gz", "type": "containers", "size": "5M", "timestamp": NOW - 7200, "encrypted": False}]}
CONT = {"containers": [{"name": "web", "state": "running", "size": "1G", "backups": 1}, {"name": "mail", "state": "stopped", "size": "2G", "backups": 0}]}
ENC = {"default_encrypt": True, "recipient_configured": True, "recipient": "age1abcdefgh…xyz012", "clear_archives": 1, "clear_names": ["web-1.tar.gz"], "key_note": "Copier la clé hors de la box."}
API = {"/status": (200, STATUS), "/list": (200, LISTE), "/containers": (200, CONT), "/encryption": (200, ENC)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    dialogues = []
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "backup":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/backup", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"code": 0, "output": "ok", "removed": []}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/backup/**", api)
    p.goto(url)
    p.dialogues = dialogues
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/backup/", API)
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tSauv", "#tClair", "#tConteneurs", "#tMarche", "#tStock")] == ["2", "1", "2", "1", "2.4G"]
    assert p.inner_text("#etat") == "ARCHIVES EN CLAIR"
    assert "CHIFFRÉE" in p.inner_text("#bHist") and "EN CLAIR" in p.inner_text("#bHist") and "1970" not in p.inner_text("#bHist")
    assert "web" in p.inner_text("#bCont") and "ARRÊTÉ" in p.inner_text("#bCont")
    assert "age1abcdefgh" in p.inner_text("#chiffrement") and err == []
    ctx.close()


def test_creer_une_sauvegarde_envoie_le_bon_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/backup/", API)
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    p.click("#bConfig")
    p.wait_for_function("document.getElementById('retour').textContent.includes('ok')")
    post = [a for a in appels if a[1] == "/create"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"type": "config", "encrypt": True}
    ctx.close()


def test_sauvegarde_en_clair_demande_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/backup/", API)
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    p.uncheck("#chiffrer"); p.click("#bFull")
    assert p.is_visible("#confirm") and "EN CLAIR" in p.inner_text("#confirmTexte")
    assert not [a for a in appels if a[1] == "/create"]
    p.click("#confirmNon")
    assert not p.is_visible("#confirm") and not [a for a in appels if a[1] == "/create"]
    p.click("#bFull"); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('ok')")
    assert json.loads([a for a in appels if a[1] == "/create"][0][2]) == {"type": "full", "encrypt": False}
    assert p.dialogues == []
    ctx.close()


def test_nettoyage_irreversible_confirme_et_conteneur_en_marche(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/backup/", {**API, "/cleanup": (200, {"code": 0, "removed": ["a", "b"], "output": "x"})})
    p.wait_for_selector("#bCont tr td.act")
    p.click("#bNettoyer")
    assert "sans retour arrière" in p.inner_text("#confirmTexte") and not [a for a in appels if a[1] == "/cleanup"]
    p.click("#confirmOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('2 ancienne')")
    assert ("POST", "/cleanup", None) in appels
    # conteneur en marche : confirmation, puis corps {name, encrypt}
    p.locator("#bCont tr").first.get_by_text("Sauvegarder").click()
    assert "arrêté" in p.inner_text("#confirmTexte")
    p.click("#confirmOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('ok')")
    assert json.loads([a for a in appels if a[1] == "/container/backup"][0][2]) == {"name": "web", "encrypt": True}
    # conteneur arrêté : direct
    p.locator("#bCont tr").nth(1).get_by_text("Sauvegarder").click()
    assert not p.is_visible("#confirm")
    assert p.dialogues == []
    ctx.close()


def test_echec_serveur_est_affiche(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/backup/", {**API, "/create": (403, {"detail": "Interdit"})})
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    p.click("#bConfig")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Interdit')")
    ctx.close()


def test_commande_de_restauration_sans_gestionnaire_en_ligne(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/backup/", API)
    p.wait_for_selector("#bHist tr td.act button")
    p.locator("#bHist tr").first.get_by_text("Commande").click()
    assert "backupctl restaurer config-1.tar.gz.age" in p.inner_text("#restaure")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/backup/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tSauv", "#tClair", "#tConteneurs", "#tMarche", "#tStock", "#tDerniere")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/backup/?demo=1", {})
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bConfig")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.click("#bNettoyer"); p.click("#confirmOui")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/backup/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bHist tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

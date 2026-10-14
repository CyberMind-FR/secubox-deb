# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /radio/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "radio" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "fonts.googleapis" not in SRC and "radio-admin.js" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'radio'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "ResizeObserver" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("/propositions/' + p.id + '/valider'", "/propositions/' + p.id + '/refuser'", "{ motif: m }",
              "/pistes/' + p.id + '/supprimer'", "/pistes/' + p.id + '/devalider'", "/pistes/' + p.id + '/bas'",
              "{ bas: !bas }", "ecrire('/suivante')", "'X-Sbx-Radio': '1'"):
        assert r in SRC, r
    # seule la méthode POST écrit, comme dans l'ancienne page
    assert "DELETE" not in SRC and "method: 'POST'" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def piste(i, titre, **kw):
    d = {"id": i, "titre": titre, "auteur": "Auteur", "duree_ms": 200000, "coeurs": 1, "source": "https://exemple.example/%d" % i,
         "en_cache": True, "bas": False, "proba": 0.0}
    d.update(kw)
    return d


P1 = piste(1, "Titre en lecture")
P2 = piste(2, "Deuxième titre", proba=0.75, aimeurs=[{"pseudo": "Aline"}], coeurs=2)
P3 = piste(3, "Titre bas", proba=0.25, bas=True)
P4 = piste(4, "Titre écarté", en_cache=False, ecarte=True, raison="vidéo privée")
P5 = piste(5, "En récupération", en_cache=False, duree_ms=0)
PLAYLIST = {"pistes": [P1, P2, P3, P4, P5], "avenir": [P2, P3], "passe": [P1]}
PROPS = {"propositions": [piste(11, "Proposition seule", en_cache=False),
                          piste(12, "Dans une liste", en_cache=False, lot="ytpl:L1", lot_titre="Ma liste")]}
CURRENT = {"silence": False, "piste": P1, "offset_ms": 50000, "horloge_ms": 1}
STATS = {"pistes": 5, "propositions": 2, "auditeurs": 9, "visites": 100}
API = {("GET", "/playlist"): (200, PLAYLIST), ("GET", "/propositions"): (200, PROPS), ("GET", "/current"): (200, CURRENT), ("GET", "/stats"): (200, STATS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "radio":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/radio", 1)[1].split("?")[0]
        q = r.request
        appels.append((q.method, chemin, q.post_data, q.headers))
        statut, corps = routes.get((q.method, chemin), (200, {"piste": {}}) if q.method == "POST" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/radio/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def charge(p):
    p.wait_for_function("document.querySelectorAll('#bPistes tr td.nom').length > 0")


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/radio/", API)
    charge(p)
    assert [p.inner_text(i) for i in ("#tAntenne", "#tValider", "#tCache", "#tEcartes", "#tAuditeurs")] == ["5", "2", "3", "1", "9"]
    assert p.inner_text("#etat") == "À L’ANTENNE"
    assert "Titre en lecture" in p.inner_text("#lecture") and "0:50 / 3:20" in p.inner_text("#lecture")
    lignes = p.inner_text("#bPistes")
    assert "EN LECTURE" in lignes and "PRÊTE" in lignes and "VIDÉO PRIVÉE" in lignes and "RÉCUPÉRATION" in lignes and "MOINS SOUVENT" in lignes
    assert "75 %" in lignes and "25 %" in lignes and "♥ Aline" in lignes
    assert "Ma liste" in p.inner_text("#bProps") and "Proposition seule" in p.inner_text("#bProps")
    assert "Deuxième titre" in p.inner_text("#avenir") and "Titre en lecture" in p.inner_text("#passe")
    assert "vidéo privée" in p.inner_text("#bEcartes").lower() and "75 %" in p.inner_text("#probas")
    # le jeton et l'en-tête d'intention accompagnent les lectures
    assert all(a[3].get("x-sbx-radio") == "1" for a in appels)
    assert err == []
    ctx.close()


def test_jeton_envoye(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/radio/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert any(a[3].get("authorization") == "Bearer jeton-test" for a in appels)
    ctx.close()


def test_moins_souvent_devalider_valider_envoient_le_bon_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/radio/", API)
    charge(p)
    ligne = p.locator("#bPistes tr", has_text="Deuxième titre")
    ligne.get_by_text("Moins souvent").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Poussée')")
    assert json.loads([a for a in appels if a[1] == "/pistes/2/bas"][0][2]) == {"bas": True}
    p.locator("#bPistes tr", has_text="Titre bas").get_by_text("Rang normal").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('rang normal')")
    assert json.loads([a for a in appels if a[1] == "/pistes/3/bas"][0][2]) == {"bas": False}
    p.locator("#bPistes tr", has_text="Deuxième titre").get_by_text("Dévalider").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Renvoyée')")
    assert ("POST", "/pistes/2/devalider", None) in [a[:3] for a in appels]
    p.locator("#bProps tr", has_text="Proposition seule").get_by_text("Valider").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Validée')")
    assert ("POST", "/propositions/11/valider", None) in [a[:3] for a in appels]
    ctx.close()


def test_refuser_saisit_le_motif_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/radio/", API)
    charge(p)
    ligne = p.locator("#bProps tr", has_text="Proposition seule")
    ligne.get_by_text("Refuser").click()
    assert not [a for a in appels if "refuser" in a[1]]          # pas encore : il faut confirmer
    ligne.locator("input").fill("hors sujet")
    ligne.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Refusée')")
    assert json.loads([a for a in appels if a[1] == "/propositions/11/refuser"][0][2]) == {"motif": "hors sujet"}
    assert err == []
    ctx.close()


def test_supprimer_et_suivante_demandent_une_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/radio/", {**API, ("POST", "/pistes/3/supprimer"): (409, {"error": "en cours de diffusion"})})
    charge(p)
    ligne = p.locator("#bPistes tr", has_text="Titre bas")
    ligne.get_by_text("Supprimer").click()
    assert not [a for a in appels if "supprimer" in a[1]]
    ligne.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('en cours de diffusion')")
    assert ("POST", "/pistes/3/supprimer", None) in [a[:3] for a in appels]
    p.click("#suivante")
    assert p.is_visible("#confSuivante") and not [a for a in appels if a[1] == "/suivante"]
    p.click("#suivOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Titre suivant')")
    assert ("POST", "/suivante", None) in [a[:3] for a in appels]
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"error": "connectez-vous"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/radio/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tAntenne", "#tValider", "#tCache", "#tEcartes", "#tAuditeurs")] == ["—"] * 5 and err == []
    ctx.close()


def test_playlist_refusee_seule_declenche_le_bandeau(navigateur):
    # ancienne page : seul le code de /propositions était examiné
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/radio/", {**API, ("GET", "/playlist"): (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/radio/?demo=1", {})
    charge(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bPistes tr").first.get_by_text("Moins souvent").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.click("#suivante"); p.click("#suivOui")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/radio/?embed=1", API, taille={"width": 420, "height": 800})
    charge(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

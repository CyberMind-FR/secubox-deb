# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2755 — /identite/ (Administration) : chaque compte de service LIÉ à une personne a un « Modifier » (relier un autre compte existant), en plus du ✕.

Vrai navigateur. Les données de la page en démonstration sont rejouées comme une API réelle (les écritures y sont inertes en mode démo, donc invérifiables)."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
DIR = Path(__file__).resolve().parents[1] / "www" / "identite"
TYPES = {".html": "text/html", ".js": "application/javascript", ".css": "text/css"}
CHEMINS = ["/moi", "/roles", "/elevation/etat", "/admin/personnes", "/admin/journal", "/admin/demandes", "/admin/communautes", "/admin/capacites", "/mesh", "/invitations"]
HTML = (DIR / "index.html").read_text(encoding="utf-8")
UID = "8a1d4c70-2b6e-4f93-b5a8-71e0c9d34f26"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def comptes(ident="ana@example.org"):
    return {"adresse": "ana@example.org", "services": {
        "courriel": {"libelle": "Courriel", "lie": True, "existe": True, "disponible": True, "identifiant": ident, "propre": True},
        "nextcloud": {"libelle": "Nextcloud", "lie": False, "existe": False, "disponible": True}}}


def ouvre(navigateur, reponses=None):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        f = DIR / (chemin[len("identite/"):] or "index.html") if chemin.startswith("identite/") else None
        if f and f.is_file():
            r.fulfill(status=200, content_type=TYPES.get(f.suffix, "text/plain"), body=f.read_text(encoding="utf-8"))
        elif chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    # 1. la page en démonstration fournit des réponses réalistes
    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=401, content_type="application/json", body="{}"))
    p.goto("http://sbx.test/identite/?demo=1")
    p.wait_for_timeout(300)
    src = HTML[HTML.index("function demoGet(chemin){"):]
    src = src[:src.index("\n}\n") + 3]
    donnees = {c: p.evaluate("([s, c]) => JSON.stringify(new Function(s + '; return demoGet(c)')())".replace("(c)')", "(' + JSON.stringify(c) + ')')"), [src, c]) for c in CHEMINS}
    donnees[f"/admin/personnes/{UID}/comptes"] = json.dumps(comptes())
    p.unroute("http://sbx.test/api/**")
    appels = []
    reponses = reponses or {}

    def api(r, *_):
        chemin = r.request.url.split("http://sbx.test/api/v1/sbxid", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if (r.request.method, chemin) in reponses:
            st, corps = reponses[(r.request.method, chemin)]
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        elif r.request.method == "GET" and chemin in donnees:
            r.fulfill(status=200, content_type="application/json", body=donnees[chemin])
        elif r.request.method == "GET":
            r.fulfill(status=404, content_type="application/json", body="{}")
        else:
            r.fulfill(status=200, content_type="application/json", body='{"ok": true, "ident": "x"}')
    p.route("http://sbx.test/api/**", api)
    p.goto("http://sbx.test/identite/#admin")
    p.wait_for_selector(f'button[data-c="{UID}"]')
    p.locator(f'button[data-c="{UID}"]').click()
    p.wait_for_selector("tr.cpt .svc")
    return ctx, p, appels


def ecritures(appels):
    return [(m, c, json.loads(b) if b else None) for m, c, b in appels if m in ("POST", "DELETE", "PUT") and "/liens/" in c or c.endswith("/lier")]


def test_un_compte_lie_a_un_bouton_modifier_pas_un_compte_non_lie(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        assert p.locator("tr.cpt .svc", has_text="Courriel").locator("button[data-modifier]").count() == 1
        assert p.locator("tr.cpt .svc", has_text="Nextcloud").locator("button[data-modifier]").count() == 0
    finally:
        ctx.close()


def test_modifier_delie_l_ancien_puis_relie_le_nouveau(navigateur):
    ctx, p, appels = ouvre(navigateur)
    try:
        p.locator("tr.cpt .svc", has_text="Courriel").locator("button[data-modifier]").click()
        champ = p.locator("tr.cpt input[data-modifier-champ]")
        assert champ.input_value() == "ana@example.org", "préremplie avec le compte actuel"
        champ.fill("ana.autre@example.org")
        p.locator("tr.cpt button[data-modifier-ok]").click()
        p.wait_for_timeout(400)
        e = ecritures(appels)
        assert e[0][0] == "DELETE" and e[0][1] == f"/admin/personnes/{UID}/liens/courriel/ana%40example.org"
        assert e[1] == ("POST", f"/admin/personnes/{UID}/lier", {"app": "courriel", "ident": "ana.autre@example.org"})
    finally:
        ctx.close()


def test_sans_changement_rien_n_est_ecrit(navigateur):
    ctx, p, appels = ouvre(navigateur)
    try:
        p.locator("tr.cpt .svc", has_text="Courriel").locator("button[data-modifier]").click()
        p.locator("tr.cpt button[data-modifier-ok]").click()
        p.wait_for_timeout(300)
        assert ecritures(appels) == []
    finally:
        ctx.close()


def test_un_nouveau_compte_refuse_remet_l_ancien_et_le_dit(navigateur):
    refus = {("POST", f"/admin/personnes/{UID}/lier"): (404, {"detail": "Compte introuvable dans le service"})}
    ctx, p, appels = ouvre(navigateur, refus)
    try:
        p.locator("tr.cpt .svc", has_text="Courriel").locator("button[data-modifier]").click()
        p.locator("tr.cpt input[data-modifier-champ]").fill("inconnu@example.org")
        p.locator("tr.cpt button[data-modifier-ok]").click()
        p.wait_for_timeout(500)
        lier = [json.loads(b) for m, c, b in appels if m == "POST" and c.endswith("/lier")]
        assert lier[0]["ident"] == "inconnu@example.org" and lier[-1] == {"app": "courriel", "ident": "ana@example.org"}, "l'ancien lien doit être remis"
        assert "introuvable" in p.locator("#toast").inner_text().lower()
    finally:
        ctx.close()


def test_annuler_ferme_l_edition_sans_rien_ecrire(navigateur):
    ctx, p, appels = ouvre(navigateur)
    try:
        p.locator("tr.cpt .svc", has_text="Courriel").locator("button[data-modifier]").click()
        p.locator("tr.cpt button[data-modifier-non]").click()
        assert p.locator("tr.cpt input[data-modifier-champ]").count() == 0
        assert ecritures(appels) == []
    finally:
        ctx.close()

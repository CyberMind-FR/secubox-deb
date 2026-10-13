# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /proxypac/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "proxypac" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'proxypac'" in SRC and "demo" in SRC and "embed" in SRC
    assert "sbx_token" in SRC


def test_garde_xss_aucun_gestionnaire_en_ligne_et_ecouteur_delegue():
    # Leçon proxypac : aucune donnée d'API dans un gestionnaire en ligne ; data-* + écouteur délégué.
    assert not re.search(r'\bon[a-z]+\s*=', SRC.split("<script>")[0].split("</style>")[1]), "gestionnaire en ligne dans le HTML"
    assert "${" not in re.sub(r"<script>.*?</script>", "", SRC, flags=re.S)
    assert "dataset.host" in SRC and "closest('[data-action]')" in SRC and "addEventListener('click'" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/wpad/apply'", "'/transparent'", "{ on }", "'/override'", "'/override/' + encodeURIComponent(host)", "'DELETE'", "'POST'"):
        assert r in SRC
    for r in ("/status", "/wpad/state", "/rules", "/candidates"):
        assert f"'{r}'" in SRC
    assert "{ host, proxy: $('proxy').value, address: $('address').value.trim() }" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


XSS = "x');alert(1);//"
STATUS = {"role": "master", "tier": 1, "dns_resolver": True, "lan_ip": "192.0.2.1", "socks_endpoint": "192.0.2.1:9050", "transparent": True, "pac_url": ""}
WPAD = {"role": "master", "domain": "example.net", "lan_ip": "192.0.2.1", "pac_url": "http://wpad.example.net/wpad.dat"}
RULES = {"rules": [{"host": "*.onion", "directive": "SOCKS5 192.0.2.1:9050"}, {"host": XSS, "directive": "DIRECT"}]}
CANDS = {"candidates": ["tracker.example.org", {"host": "cdn.example.net"}]}
API = {"/status": (200, STATUS), "/wpad/state": (200, WPAD), "/rules": (200, RULES), "/candidates": (200, CANDS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, dialogues = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "proxypac":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/proxypac", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"ok": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/proxypac/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels, dialogues


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _, dlg = ouvre(navigateur, "http://sbx.test/proxypac/", API)
    p.wait_for_selector("#bRegles tr td.mono", state="attached")
    assert p.inner_text("#tRole") == "master / niveau 1" and p.inner_text("#tWpad") == "master"
    assert p.inner_text("#tSocks") == "192.0.2.1:9050" and p.inner_text("#tLan") == "192.0.2.1"
    assert p.inner_text("#tTrans") == "ACTIF" and p.inner_text("#tRegles") == "2" and p.inner_text("#etat") == "ACTIF"
    assert "*.onion" in p.inner_text("#bRegles") and "SOCKS5 192.0.2.1:9050" in p.inner_text("#bRegles")
    # URL WPAD réelle (état serveur), jamais le texte en dur de l'ancienne page
    assert p.inner_text("#dWpad") == "http://wpad.example.net/wpad.dat" and p.inner_text("#dPac") == "http://192.0.2.1/proxy.pac"
    assert "tracker.example.org" in p.inner_text("#bCand") and "cdn.example.net" in p.inner_text("#bCand")
    assert err == [] and dlg == []
    ctx.close()


def test_hote_hostile_reste_du_texte_et_la_suppression_demande_confirmation(navigateur):
    ctx, p, err, appels, dlg = ouvre(navigateur, "http://sbx.test/proxypac/", API)
    p.wait_for_selector("#bRegles tr td.act")
    p.locator("#bRegles tr").nth(1).get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]                      # il faut confirmer
    assert not p.is_hidden("#confirm") and XSS in p.inner_text("#confirmTexte")
    p.click("#confirmOui")
    p.wait_for_function("document.getElementById('rRegles').textContent.length > 0")
    assert ("DELETE", "/override/" + "x')%3Balert(1)%3B%2F%2F", None) in appels
    # l'API simulée renvoie encore la règle : la page le dit au lieu d'annoncer un faux succès
    assert "toujours présente" in p.inner_text("#rRegles")
    assert err == [] and dlg == []
    ctx.close()


def test_annuler_la_confirmation_n_envoie_rien(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/", API)
    p.wait_for_selector("#bRegles tr td.act")
    p.locator("#bRegles tr").first.get_by_text("Supprimer").click()
    p.click("#confirmNon")
    assert p.is_hidden("#confirm") and not [a for a in appels if a[0] != "GET"]
    ctx.close()


def test_bascule_transparent_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/", API)
    p.wait_for_function("!document.getElementById('bascule').disabled")
    p.click("#bascule")
    assert not [a for a in appels if a[1] == "/transparent"]
    p.click("#confirmOui")
    p.wait_for_function("document.getElementById('rTrans').textContent.includes('désactivé')")
    assert ("POST", "/transparent", '{"on":false}') in appels
    ctx.close()


def test_echec_transparent_affiche_le_detail(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, "http://sbx.test/proxypac/", {**API, "/transparent": (200, {"ok": False, "detail": "torctl refuse"})})
    p.wait_for_function("!document.getElementById('bascule').disabled")
    p.click("#bascule"); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('rTrans').textContent.includes('échouée')")
    assert "torctl refuse" in p.inner_text("#rTrans")
    ctx.close()


def test_appliquer_wpad_et_ajouter_une_regle(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/", API)
    p.wait_for_selector("#bRegles tr td.mono", state="attached")
    p.click("#wpadApply"); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('rTrans').textContent.includes('WPAD appliqué')")
    assert ("POST", "/wpad/apply", None) in appels
    p.fill("#host", "bank.example"); p.select_option("#proxy", "socks5"); p.fill("#address", "192.0.2.10:9050")
    p.click("#fOverride button[type=submit]")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('ajoutée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/override"][0]
    assert json.loads(post[2]) == {"host": "bank.example", "proxy": "socks5", "address": "192.0.2.10:9050"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/proxypac/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tRole", "#tWpad", "#tSocks", "#tTrans", "#tLan", "#tRegles", "#dWpad")] == ["—"] * 7 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/proxypac/?demo=1", {})
    p.wait_for_selector("#bRegles tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert "192.0.2.1" in p.inner_text("#tLan")
    p.locator("#bRegles tr").first.get_by_text("Supprimer").click(); p.click("#confirmOui")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/proxypac/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bRegles tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

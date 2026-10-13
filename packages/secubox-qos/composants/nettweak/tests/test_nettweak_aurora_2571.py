# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /nettweak/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "nettweak" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'nettweak'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    assert len(re.findall(r"ecrire\('(?:POST|DELETE|PUT)'", SRC)) == 4
    assert SRC.count("ecrire('POST', '/apply', { settings: reglages, persist: true })") == 1
    assert SRC.count("ecrire('POST', '/apply', { profile: id, persist: true })") == 1
    assert "ecrire('POST', '/reload')" in SRC and "ecrire('POST', '/reset')" in SRC
    assert "/set/" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def m(value, description, **extra):
    return {"value": value, "description": description, "default": None, "type": "int", "unit": "", **extra}


STATUS = {"active_profile": "performance", "saved_settings_count": 4, "config_file": "/etc/sysctl.d/90-secubox-nettweak.conf", "config_exists": True,
          "available_congestion_controls": ["reno", "cubic", "bbr"], "summary": {"tcp_congestion_control": "bbr", "ip_forwarding": True, "tcp_fastopen": "3"},
          "timestamp": "2026-10-13T10:00:00"}
PROFILES = {"profiles": [{"id": "default", "name": "Default", "description": "Defauts", "settings_count": 0, "active": False},
                         {"id": "performance", "name": "Performance", "description": "Haut debit", "settings_count": 2, "active": True}], "current": "performance"}
TCP = {"settings": {"net.ipv4.tcp_congestion_control": m("bbr", "Congestion", type="string", options=["cubic", "reno", "bbr"]),
                    "net.ipv4.tcp_syncookies": m("1", "Cookies SYN", type="bool"),
                    "net.ipv4.tcp_fin_timeout": m("30", "Delai FIN", unit="secondes", default=60)}}
NET = {"settings": {"net.core.rmem_max": m("16777216", "Tampon reception", unit="octets"), "net.ipv4.ip_forward": m("1", "Routage", type="bool")}}
TOUS = {"settings": {**TCP["settings"], **NET["settings"]}, "saved": {}}
PROFIL = {"id": "performance", "name": "Performance", "description": "x", "settings": [
    {"key": "net.core.rmem_max", "profile_value": "16777216", "current_value": "16777216", "description": "", "matches": True},
    {"key": "net.ipv4.tcp_fin_timeout", "profile_value": "15", "current_value": "30", "description": "", "matches": False}]}
API = {"/status": (200, STATUS), "/profiles": (200, PROFILES), "/settings": (200, TOUS), "/tcp": (200, TCP), "/net": (200, NET), "/profile/performance": (200, PROFIL)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "nettweak":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/nettweak", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/nettweak/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/nettweak/", API)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tProfil", "#tCc", "#tFwd", "#tSaved", "#tFic")] == ["Performance", "bbr", "Actif", "4", "Oui"]
    assert p.inner_text("#etat") == "PROFIL : PERFORMANCE"
    assert "net.core.rmem_max" in p.inner_text("#bCles") and "16777216 octets" in p.inner_text("#bCles")
    assert "—" in p.inner_text("#bCles")  # clés absentes de l'API : tiret, pas de valeur inventée
    p.click("#o-tcp")
    assert "net.ipv4.tcp_fin_timeout" in p.inner_text("#bTcp") and "(secondes)" in p.inner_text("#bTcp")
    p.click("#o-profils")
    assert "Performance" in p.inner_text("#listeProfils") and "ACTIF" in p.inner_text("#listeProfils")
    p.get_by_role("button", name="Performance").first.click()
    p.wait_for_selector("#bDetail tr td.mono", state="attached")
    assert "IDENTIQUE" in p.inner_text("#bDetail") and "DIFFÉRENT" in p.inner_text("#bDetail")
    assert err == []
    ctx.close()


def test_enregistrer_confirme_dans_la_page_puis_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/nettweak/", {**API, "/apply": (200, {"success": True, "applied": 2, "errors": 0, "persisted": True, "results": []})})
    p.click("#o-tcp")
    p.wait_for_selector("#bTcp tr")
    ligne = p.locator("#bTcp tr", has_text="tcp_fin_timeout")
    ligne.locator("input").fill("15"); ligne.locator("input").dispatch_event("change")
    p.locator("#bTcp tr", has_text="tcp_syncookies").locator("select").select_option("0")
    assert p.inner_text("#saveTcp") == "Enregistrer (2)"
    p.click("#saveTcp")
    assert p.is_visible("#conf") and "30 → 15" in p.inner_text("#confListe")
    assert ecritures(appels) == []                        # pas d'écriture avant confirmation
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('appliqué')")
    ec = ecritures(appels)
    assert len(ec) == 1 and ec[0][:2] == ("POST", "/apply")
    assert json.loads(ec[0][2]) == {"settings": {"net.ipv4.tcp_fin_timeout": "15", "net.ipv4.tcp_syncookies": "0"}, "persist": True}
    assert err == []
    ctx.close()


def test_profil_demande_confirmation_et_annuler_n_ecrit_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/nettweak/", {**API, "/apply": (200, {"success": True, "applied": 2, "errors": 0, "persisted": True})})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    p.click("[data-prof=security]")
    assert p.is_visible("#conf") and "Appliquer le profil" in p.inner_text("#confTitre")
    p.click("#confNon")
    assert not p.is_visible("#conf") and ecritures(appels) == []
    p.click("[data-prof=security]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('appliqué')")
    assert json.loads(ecritures(appels)[0][2]) == {"profile": "security", "persist": True}
    ctx.close()


def test_rechargement_et_reinitialisation_confirmes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/nettweak/", API)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    p.click("#recharger"); assert ecritures(appels) == []; p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('rechargée')")
    p.click("#reinit"); assert len(ecritures(appels)) == 1; p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('supprimée')")
    assert [a[:2] for a in ecritures(appels)] == [("POST", "/reload"), ("POST", "/reset")]
    ctx.close()


def test_echec_d_application_affiche_la_cle_refusee(navigateur):
    ech = {"success": False, "applied": 1, "errors": 1, "persisted": False, "results": [
        {"key": "net.ipv4.tcp_congestion_control", "value": "x", "success": False, "error": "sysctl: invalid argument"}]}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/nettweak/", {**API, "/apply": (200, ech)})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    p.click("[data-prof=router]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Échec')")
    t = p.inner_text("#retour")
    assert "tcp_congestion_control" in t and "invalid argument" in t and "non enregistré" in t
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/nettweak/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tProfil", "#tCc", "#tFwd", "#tSaved", "#tFic")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/nettweak/?demo=1", {})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("[data-prof=router]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.click("#o-profils"); p.get_by_role("button", name="Performance").first.click()
    p.wait_for_selector("#bDetail tr td.mono", state="attached")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/nettweak/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    for o in ("#o-tcp", "#o-net", "#o-profils", "#o-apercu"):
        p.click(o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

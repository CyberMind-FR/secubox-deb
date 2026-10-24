# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /netboot/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "netboot" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "health-banner" not in SRC and "crt-light" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'netboot'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    vus = set(re.findall(r"ecrire\('(POST|DELETE)', ('[^']+'(?: \+ encodeURIComponent\(id\))?)", SRC))
    assert vus == {
        ("POST", "'/overlay/apply'"), ("POST", "'/overlay/revert'"), ("POST", "'/overlay/persist'"),
        ("POST", "'/overlay/confirm-healthy'"), ("POST", "'/server/up'"), ("POST", "'/publish'"),
        ("POST", "'/profiles'"), ("DELETE", "'/profiles/' + encodeURIComponent(id)"),
        ("POST", "'/flash/prepare'"),   # #3100 : préparer un flash
    }
    assert "{ confirm: !!commit }" in SRC and "{ confirm: true }" in SRC and "{ board_id: id }" in SRC
    assert "boot_level: v('boot_level')" in SRC and "srv: v('srv') || null" in SRC
    assert "method: 'PUT'" not in SRC and "PATCH" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


INV = {"board": {"board": {"model": "mochabin", "soc": "Armada 7040"}, "firmware": {"tfa": "v2.8(release)", "uboot_version": "2023.04"},
                 "media": {"spi_firmware_mtd": "mtd0", "emmc": "yes", "emmc_ab_slots": "yes"},
                 "capabilities": {"wget": "likely", "bootm_fit": "likely"}, "overlay_ready": True},
       "overlay": {"env_ok": "yes", "overlay_active": "no", "persisted": "no", "fit_deployed": "yes", "bootcount": "0", "has_factory_backup": "yes"}}
SERVER = {"server": {"tftp_root": "/srv/t", "http_root": "/srv/h", "tftpd": "active", "nginx_sbxboot": "yes", "published_boards": 2}}
PROFILES = {"profiles": [{"id": "02005e005301", "model": "mochabin", "image": "secubox-2.39.0", "boot_level": "B2", "srv": "192.0.2.10"},
                         {"id": "02005e005302", "model": "x", "image": None, "boot_level": "B0", "srv": None}]}
API = {"/inventory": (200, INV), "/shadow": (200, {"items": [{"name": "overlay.fit", "size": 100}]}),
       "/audit": (200, {"audit": ["evt-un", "evt-deux"]}), "/server": (200, SERVER), "/profiles": (200, PROFILES),
       "/boards": (200, {"boards": [{"model": "mochabin"}]})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif"), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "netboot":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/netboot", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if (r.request.method + " " + chemin) in routes:
            statut, corps = routes[r.request.method + " " + chemin]
        elif r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"ok": True, "result": "fait"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/netboot/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netboot/", API)
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tModele", "#tEnv", "#tOverlay", "#tSrv", "#tPub", "#tProf")] == ["mochabin", "Oui", "Non", "Actif", "2", "2"]
    assert p.inner_text("#etat") == "SERVEUR ACTIF"
    assert "02005e005301" in p.inner_text("#bProf") and "B2 HTTP signé" in p.inner_text("#bProf") and "DHCP" in p.inner_text("#bProf")
    assert "overlay.fit" in p.inner_text("#shadow") and "evt-un" in p.inner_text("#audit")
    assert "Armada 7040" in p.inner_text("#kBoard") and not p.is_disabled("#bApply")
    assert err == []
    ctx.close()


def test_application_reelle_demande_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/", API)
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    p.click("#bApply")
    assert p.is_visible("#conf") and "bootcmd" in p.inner_text("#confTexte")
    assert not [a for a in appels if a[1] == "/overlay/apply"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rOverlay').textContent.includes('APPLICATION')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/overlay/apply"] == [{"confirm": True}]
    p.click("#bDry")
    p.wait_for_function("document.getElementById('rOverlay').textContent.includes('SIMULATION')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/overlay/apply"][-1] == {"confirm": False}
    assert err == []
    ctx.close()


def test_annuler_n_envoie_rien_et_publication_et_suppression(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/", API)
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    p.click("#bRevert"); p.click("#confNon")
    assert not [a for a in appels if a[1] == "/overlay/revert"] and not p.is_visible("#conf")
    p.locator("#bProf tr").first.get_by_text("Publier").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rProf').textContent.includes('PUBLICATION')")
    assert json.loads([a for a in appels if a[1] == "/publish"][0][2]) == {"board_id": "02005e005301"}
    assert p.locator("#bProf tr").nth(1).get_by_text("Publier").is_disabled()
    p.locator("#bProf tr").first.locator("button.danger").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rProf').textContent.includes('supprimé')")
    assert ("DELETE", "/profiles/02005e005301", None) in appels
    p.click("#bUp"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServeur').textContent.includes('SERVEUR ACTIVÉ')")
    assert ("POST", "/server/up", None) in appels
    assert err == []
    ctx.close()


def test_enregistrer_un_profil_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/", API)
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    p.fill("#fProf [name=id]", "02:00:5e:00:53:09"); p.fill("#fProf [name=image]", "secubox-2.40.0")
    p.select_option("#fProf [name=boot_level]", "B1"); p.fill("#fProf [name=srv]", "")
    p.click("#fProf button[type=submit]")
    p.wait_for_function("document.getElementById('rProf').textContent.includes('enregistré')")
    corps = json.loads([a for a in appels if a[0] == "POST" and a[1] == "/profiles"][0][2])
    assert corps == {"id": "02:00:5e:00:53:09", "model": None, "image": "secubox-2.40.0", "boot_level": "B1", "srv": None}
    ctx.close()


def test_erreur_422_lisible(navigateur):
    routes = {**API, "POST /profiles": (422, {"detail": [{"msg": "champ invalide"}]})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/netboot/", routes)
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    p.fill("#fProf [name=id]", "zz"); p.click("#fProf button[type=submit]")
    p.wait_for_function("document.getElementById('rProf').textContent.includes('champ invalide')")
    assert "[object" not in p.inner_text("#rProf")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netboot/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tModele", "#tEnv", "#tOverlay", "#tSrv", "#tPub", "#tProf")] == ["—"] * 6
    assert p.is_disabled("#bApply") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/?demo=1", {})
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bApply"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rOverlay').textContent.includes('inerte')")
    p.click("#bDry")
    p.wait_for_function("document.getElementById('rOverlay').textContent.includes('SIMULATION impossible')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netboot/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bProf tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


LIVES = {"lives": [{"nom": "mochabin-live", "serveur": "192.0.2.10", "http_base": "http://192.0.2.10:8099/mochabin-live",
                    "squashfs": True, "commandes": ["setenv ethact mvpp2-2; setenv serverip 192.0.2.10",
                                                    "tftpboot ${scriptaddr} mochabin-live/boot.scr; source ${scriptaddr}"],
                    "images": [{"nom": "secubox-isp-mochabin-trixie.img.gz", "taille": 2669000177, "sha256": "a" * 64, "signee": True}]}]}


def test_3100_netbooter_et_preparer_un_flash(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/netboot/", {**API, "/live": (200, LIVES)})
    p.wait_for_selector("#lives pre", state="attached")
    texte = p.inner_text("#lives")
    assert "tftpboot ${scriptaddr} mochabin-live/boot.scr" in texte and "sbx-netflash --nom NOM" in texte
    assert "secubox-isp-mochabin-trixie.img.gz" in texte and "2,67 Go" in texte and "signée" in texte
    assert p.get_attribute("#lives a", "href") == "http://192.0.2.10:8099/mochabin-live/images.txt"
    # nom invalide : rien n'est envoyé
    p.fill("#fFlash input[name=nom]", "../x"); p.click("#fFlash button[type=submit]")
    assert not [a for a in appels if a[1] == "/flash/prepare"]
    # confirmation dans la page, mot de passe envoyé une fois puis effacé du formulaire
    p.fill("#fFlash input[name=nom]", "gk4"); p.fill("#fFlash input[name=mot_de_passe]", "Secret-Test-42")
    p.click("#fFlash button[type=submit]")
    assert p.is_visible("#conf") and "gk4" in p.inner_text("#confTexte")
    assert p.input_value("#fFlash input[name=mot_de_passe]") == ""
    assert not [a for a in appels if a[1] == "/flash/prepare"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rFlash').textContent.includes('sbx-netflash --nom gk4')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/flash/prepare"] == [{"nom": "gk4", "mot_de_passe": "Secret-Test-42"}]
    assert err == []
    ctx.close()


def test_3100_aucun_live_publie(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/netboot/", {**API, "/live": (200, {"lives": []})})
    p.wait_for_function("document.getElementById('lives').textContent.includes('Aucun live')")
    assert err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /vm/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "vm" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'vm'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "Authorization" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/vms/lxc'", "'/vms/kvm'", "'DELETE'", "stop?hold=true", "/autostart?on=", "'unfreeze'", "'freeze'", "'restart'", "'start'", "'stop'"):
        assert r in SRC, r
    assert "disk_size" in SRC and "template" in SRC and "release" in SRC
    # l'ancienne page n'avait pas de suppression ni de clonage de conteneur
    assert "clone" not in SRC.lower() and "docker" not in SRC.lower() and "podman" not in SRC.lower()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"libvirt": {"available": True, "kvm_enabled": True}, "lxc": {"available": True}, "vms": {"total": 2, "running": 1}, "containers": {"total": 3, "running": 1}}
VMS = {"vms": [
    {"id": "3", "name": "kvm-un", "state": "running", "type": "kvm"},
    {"id": None, "name": "kvm-deux", "state": "shut off", "type": "kvm"},
    {"name": "lxc-marche", "state": "running", "frozen": False, "ip": "192.0.2.10", "memory": "412.30MB", "autostart": True, "type": "lxc"},
    {"name": "lxc-veille", "state": "frozen", "frozen": True, "ip": "192.0.2.11", "memory": "96.00MB", "autostart": False, "type": "lxc"},
    {"name": "lxc-arret", "state": "stopped", "frozen": False, "ip": None, "memory": "0.00MB", "autostart": False, "type": "lxc"}]}
API = {"/status": (200, STATUS), "/vms": (200, VMS), "/iso": (200, {"images": [{"name": "d.iso", "size_human": "1.0 GB"}]}),
       "/templates": (200, {"templates": [{"name": "debian", "releases": ["bookworm"]}, {"name": "alpine", "releases": ["3.19", "edge"]}]})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "vm":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        brut = r.request.url.split("/api/v1/vm", 1)[1]
        chemin = brut.split("?")[0]
        appels.append((r.request.method, brut, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method != "GET":
            statut, corps = routes.get(chemin, (200, {"status": "ok"}))
        else:
            statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/vm/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/vm/", API)
    p.wait_for_selector("#b-toutes tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tLxc", "#tLxcOn", "#tKvm", "#tKvmOn")] == ["3", "1", "2", "1"]
    assert p.inner_text("#tLibvirt") == "Actif" and p.inner_text("#etat") == "EN LIGNE"
    txt = p.inner_text("#b-toutes")
    assert "lxc-marche" in txt and "192.0.2.10" in txt and "412.30MB" in txt and "EN VEILLE" in txt and "ÉTEINTE" in txt
    # mémoire « 0.00MB » d'un conteneur arrêté : jamais présentée comme mesure
    assert "0.00MB" not in txt
    assert p.locator("#b-toutes tr").count() == 5 and p.locator("#b-kvm tr").count() == 2 and p.locator("#b-lxc tr").count() == 3
    assert err == []
    ctx.close()


def test_jeton_envoye_et_noms_non_interpretes(navigateur):
    vms = {"vms": [{"name": "<img src=x onerror=window.__x=1>", "state": "stopped", "type": "lxc", "autostart": False}]}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/vm/", {**API, "/vms": (200, vms)})
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_function("document.getElementById('b-toutes').textContent.includes('<img')")
    assert p.evaluate("window.__x") is None and p.locator("#b-toutes img").count() == 0
    assert any(a[3] == "Bearer jeton-test" for a in appels[2:])
    ctx.close()


def test_demarrer_arreter_demandent_une_confirmation_nommee(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vm/", API)
    p.wait_for_selector("#b-toutes tr td.act")
    ligne = p.locator("#b-toutes tr", has_text="lxc-arret")
    ligne.get_by_text("Démarrer").click()
    assert "Démarrer lxc-arret ?" in p.inner_text("#b-toutes") and not ecritures(appels)
    ligne.get_by_text("Annuler").click()
    assert not ecritures(appels)
    ligne.get_by_text("Démarrer").click(); ligne.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('lxc-arret')")
    assert ("POST", "/vms/lxc-arret/start") == ecritures(appels)[0][:2]
    p.locator("#b-toutes tr", has_text="lxc-marche").get_by_text("Arrêter").click()
    assert "Arrêter lxc-marche ?" in p.inner_text("#b-toutes")
    p.locator("#b-toutes").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('arrêté')")
    assert ("POST", "/vms/lxc-marche/stop") == ecritures(appels)[1][:2]
    ctx.close()


def test_couper_veille_reveil_autostart_memes_routes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vm/", API)
    p.wait_for_selector("#b-toutes tr td.act")
    m = p.locator("#b-toutes tr", has_text="lxc-marche")
    m.get_by_text("Couper").click(); m.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('coupé')")
    m.get_by_text("Veille").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('veille')")
    p.locator("#b-toutes tr", has_text="lxc-veille").get_by_text("Réveiller").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('réveillé')")
    m.get_by_text("Auto : activé").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('désactivé')")
    assert [a[:2] for a in ecritures(appels)] == [("POST", "/vms/lxc-marche/stop?hold=true"), ("POST", "/vms/lxc-marche/freeze"),
                                                  ("POST", "/vms/lxc-veille/unfreeze"), ("POST", "/vms/lxc-marche/autostart?on=false")]
    ctx.close()


def test_supprimer_une_machine_kvm_confirme_puis_delete(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vm/", API)
    p.wait_for_selector("#b-toutes tr td.act")
    assert p.locator("#b-lxc >> text=Supprimer").count() == 0 and p.locator("#b-kvm >> text=Supprimer").count() == 2
    p.click("#o-kvm")
    l = p.locator("#b-kvm tr", has_text="kvm-deux")
    l.get_by_text("Supprimer").click()
    assert "Supprimer kvm-deux définitivement ?" in p.inner_text("#b-kvm") and not ecritures(appels)
    l.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('supprimé')")
    assert ecritures(appels)[0][:2] == ("DELETE", "/vms/kvm-deux")
    ctx.close()


def test_creation_envoie_les_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vm/", API)
    p.wait_for_selector("#b-toutes tr")
    p.click("#addLxc"); p.wait_for_selector("#lxcTemplate option[value=alpine]", state="attached")
    p.fill("#fLxc [name=name]", "neuf"); p.select_option("#lxcTemplate", "alpine"); p.select_option("#lxcRelease", "edge")
    p.click("#fLxc button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('créé')")
    p.click("#addKvm"); p.wait_for_selector("#kvmIso option[value='d.iso']", state="attached")
    p.fill("#fKvm [name=name]", "vm-neuve"); p.select_option("#kvmIso", "d.iso")
    p.click("#fKvm button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Machine vm-neuve')")
    w = ecritures(appels)
    assert w[0][:2] == ("POST", "/vms/lxc") and json.loads(w[0][2]) == {"name": "neuf", "template": "alpine", "release": "edge"}
    assert w[1][:2] == ("POST", "/vms/kvm") and json.loads(w[1][2]) == {"name": "vm-neuve", "memory": 2048, "vcpus": 2, "disk_size": 20, "iso": "d.iso"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/vm/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tLxc", "#tLxcOn", "#tKvm", "#tKvmOn", "#tLibvirt", "#tLxcDispo")] == ["—"] * 6 and err == []
    ctx.close()


def test_moteur_absent_donne_des_tirets_pas_des_zeros(navigateur):
    st = {**STATUS, "libvirt": {"available": False, "kvm_enabled": False}, "vms": {"total": 0, "running": 0}}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/vm/", {**API, "/status": (200, st)})
    p.wait_for_selector("#b-toutes tr td.mono", state="attached")
    assert p.inner_text("#tKvm") == "—" and p.inner_text("#tKvmOn") == "—" and p.inner_text("#tLibvirt") == "Arrêté"
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/vm/?demo=1", {})
    p.wait_for_selector("#b-toutes tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and "192.0.2." in p.inner_text("#b-toutes")
    p.locator("#b-toutes tr", has_text="essai-exemple").get_by_text("Démarrer").click()
    p.locator("#b-toutes").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/vm/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#b-toutes tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

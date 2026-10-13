# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /qos/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "qos" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'qos'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    # POST /vlan/create, DELETE /vlan/{iface}, POST /vlan/{iface}/policy, POST /vlan/apply_all, POST /pcp/enable?enabled=
    for r in ("'/vlan/create'", "'DELETE'", "'/vlan/' + encodeURIComponent(f.interface.value) + '/policy'", "'/vlan/apply_all'", "'/pcp/enable?enabled=' + voulu"):
        assert r in SRC
    assert len(re.findall(r"ecrire\('(?:POST|DELETE)'", SRC)) == 5
    # la page lit les vraies formes de l'API (liste nue pour classes/regles) et pas les champs inexistants
    for faux in ("active_rules", "shaped_clients", "c.usage", "r.match,", "c.rate,"):
        assert faux not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"enabled": True, "qos_active": True, "interface": "eth0", "upload_mbps": 100, "download_mbps": 200,
          "stats": {"rx_bytes": 2048, "tx_bytes": 1048576, "rx_packets": 1, "tx_packets": 1}}
CLASSES = [{"classid": "1:10", "name": "Voix", "rate_kbps": 20000, "ceil_kbps": 0, "priority": 0, "parent": "1:1"},
           {"classid": "1:40", "name": "Masse", "rate_kbps": 800, "ceil_kbps": 50000, "priority": 3, "parent": "1:1"}]
RULES = [{"name": "visio", "match_type": "ip", "match_value": "192.0.2.40", "class_id": "1:10", "priority": 10, "enabled": True},
         {"name": "invites", "match_type": "port", "match_value": "873", "class_id": "1:40", "priority": 20, "enabled": False}]
VLANS = {"vlans": [{"interface": "eth0.100", "vlan_id": 100, "parent": "eth0", "state": "UP", "mtu": 1500,
                    "policy": {"upload_mbps": 50, "download_mbps": 100, "priority": 5, "description": "Tel", "enabled": True}, "qos_enabled": True},
                   {"interface": "eth0.200", "vlan_id": 200, "parent": "eth0", "state": "UP", "mtu": 1500, "policy": None, "qos_enabled": False}], "count": 2}
IFACES = {"interfaces": [{"interface": "eth0", "is_vlan": False, "vlan_id": None, "stats": {"rx_bytes": 2048, "tx_bytes": 1048576}, "qos_active": True}], "count": 1}
PCP = {"default_mappings": {"realtime": 7, "voice": 6, "best_effort": 0}, "custom_mappings": {}, "pcp_enabled": False}
API = {"/status": (200, STATUS), "/classes": (200, CLASSES), "/rules": (200, RULES), "/vlans": (200, VLANS), "/interfaces": (200, IFACES), "/pcp/mappings": (200, PCP)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "qos":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/qos", 1)[1].split("#")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        sans_requete = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(sans_requete, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + sans_requete, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/qos/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/qos/", API)
    p.wait_for_selector("#bClasses tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tEtat", "#tDown", "#tUp", "#tRegles", "#tVlan")] == ["Actif", "200", "100", "1", "2"]
    assert p.inner_text("#sRegles") == "sur 2" and p.inner_text("#etat") == "QOS ACTIF"
    classes = p.inner_text("#bClasses")
    assert "Voix" in classes and "20 Mbit/s" in classes and "800 kbit/s" in classes and "50 Mbit/s" in classes
    assert p.locator("#bClasses tr").first.locator("td").nth(4).inner_text() == "—"     # ceil 0 = non défini
    assert "192.0.2.40" in p.inner_text("#bRegles") and "ACTIVE" in p.inner_text("#bRegles") and "INACTIVE" in p.inner_text("#bRegles")
    assert "eth0.100" in p.inner_text("#bVlan") and "50 Mbit/s" in p.inner_text("#bVlan") and "PCP 5" in p.inner_text("#bVlan")
    assert "2 Kio" in p.inner_text("#bIf") and "1 Mio" in p.inner_text("#bIf")
    assert "realtime" in p.inner_text("#bPcp") and not p.is_checked("#pcpOn")
    assert err == []
    ctx.close()


def test_creer_un_vlan_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/qos/", API)
    p.wait_for_selector("#bVlan tr td.mono", state="attached")
    p.click("#addVlan")
    p.fill("#fVlan [name=vlan_id]", "300"); p.fill("#fVlan [name=description]", "Gestion")
    p.click("#fVlan button[type=submit]")
    p.wait_for_function("document.getElementById('rVlan').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/vlan/create"][0]
    assert json.loads(post[2]) == {"parent": "eth0", "vlan_id": 300, "upload_mbps": 100, "download_mbps": 200, "priority": 0, "description": "Gestion"}
    ctx.close()


def test_supprimer_demande_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/qos/", API)
    p.wait_for_selector("#bVlan tr td.act")
    p.locator("#bVlan tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bVlan tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rVlan').textContent.includes('supprimé')")
    assert ("DELETE", "/vlan/eth0.100", None) in appels
    ctx.close()


def test_modifier_la_politique_et_tout_appliquer(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/qos/", {**API, "POST /vlan/apply_all": (200, {"success": True, "count": 2})})
    p.wait_for_selector("#bVlan tr td.act")
    p.locator("#bVlan tr").first.get_by_text("Modifier").click()
    p.fill("#fEdit [name=upload_mbps]", "70"); p.click("#fEdit button[type=submit]")
    p.wait_for_function("document.getElementById('rVlan').textContent.includes('enregistrée')")
    post = [a for a in appels if a[1] == "/vlan/eth0.100/policy"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"upload_mbps": 70, "download_mbps": 100, "priority": 5, "enabled": True, "description": "Tel"}
    p.click("#toutAppliquer")
    assert not [a for a in appels if a[1] == "/vlan/apply_all"]
    p.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rVlan').textContent.includes('2 interface')")
    ctx.close()


def test_pcp_envoie_la_requete_et_revient_en_arriere_si_refus(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/qos/", {**API, "POST /pcp/enable": (500, {"detail": "boum"})})
    p.wait_for_selector("#bPcp tr td.mono", state="attached")
    p.click("#pcpOn")
    p.wait_for_function("document.getElementById('rPcp').textContent.includes('impossible')")
    assert ("POST", "/pcp/enable?enabled=true", None) in appels and not p.is_checked("#pcpOn")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/qos/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEtat", "#tDown", "#tUp", "#tRegles", "#tVlan")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/qos/?demo=1", {})
    p.wait_for_selector("#bVlan tr td.act")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bVlan tr").first.get_by_text("Supprimer").click(); p.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rVlan').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/qos/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bClasses tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2550 — /p2p/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "p2p" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "lorem", "innerHTML"):
        assert interdit not in SRC.lower() if interdit == "lorem" else interdit not in SRC
    assert "sbxVue" in SRC and "onglet: 'p2p'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique_et_sonde_sur_la_vraie_route():
    for r in ("'/peers'", "'/services'", "/services/auto-register", "'/request'", "'activate'", "'revoke-access'", "'request'"):
        pass
    for r in ("/peers", "/services", "/services/auto-register", "/probe", "'activate'", "'revoke-access'", "'request'", "DELETE"):
        assert r in SRC
    assert "/ping" not in SRC  # cette route n'a jamais existé côté API : la sonde est /probe
    assert "p2p-local" in SRC and "peer_id" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"online": True, "node_id": "gk2-4f9a", "hostname": "gk2", "lan_ip": "192.0.2.1", "wan_ip": "198.51.100.7", "total_peers": 4, "active_peers": 3,
          "liveness": "measured", "service_count": 2, "threat_count": 1, "master_link": {"role": "master", "depth": 0, "upstream": None}, "version": "1.3.0"}
PEERS = {"peers": [{"id": "gk1", "name": "gk1", "address": "10.10.0.3", "status": "online", "latency": None, "last_seen": NOW - 30},
                   {"id": "c3box", "name": "c3box", "address": "10.10.0.2", "status": "offline", "latency": None, "last_seen": None}], "count": 2}
SERVICES = {"services": [{"name": "tor-socks", "type": "socks", "provider_label": "local", "port": 9050, "active": True, "subscription_state": "n/a", "source": "p2p-local"},
                         {"name": "dns", "type": "udp", "provider_label": "did:x", "port": 53, "active": False, "subscription_state": "not-subscribed", "source": "annuaire", "service_id": "svc-1"}]}
MESH = {"nodes": [{"id": "gk2-4f9a", "name": "gk2", "address": "10.10.0.1", "status": "online", "is_local": True},
                  {"id": "gk1", "name": "gk1", "address": "10.10.0.3", "status": "online", "is_local": False},
                  {"id": "c3box", "name": "c3box", "address": "10.10.0.2", "status": "offline", "is_local": False}]}
THREATS = {"threats": {"203.0.113.9": {"ip": "203.0.113.9", "reason": "Balayage de ports", "severity": "high", "reported": "2026-10-12T21:40:00", "reporter": "gk1"}}}
TOPO = {"enabled": True, "master": "a1b2c3d4e5f6a7b8c9", "term": 7, "self_role": "master", "self_id": "aa", "peers": []}
DHT = {"enabled": True, "peers": [{"did": "x"}], "buckets": 1}
API = {"/status": (200, STATUS), "/peers": (200, PEERS), "/services": (200, SERVICES), "/mesh": (200, MESH), "/threats": (200, THREATS),
       "/masterlink/topology": (200, TOPO), "/dht/peers": (200, DHT)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "p2p":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/p2p", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"status": "ok"})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/p2p/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/p2p/", API)
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tPairs", "#tVivants", "#tServices", "#tMenaces", "#tRole")] == ["4", "3", "2", "1", "Maître"]
    assert p.inner_text("#etat") == "EN LIGNE" and "gk1" in p.inner_text("#bPairs") and "HORS LIGNE" in p.inner_text("#bPairs")
    # la dernière poignée de main est en SECONDES : jamais « 1970 »
    assert "1970" not in p.inner_text("#bPairs") and "il y a" in p.inner_text("#bPairs")
    # /threats renvoie {"threats": {...}} : la vraie adresse est listée, pas une ligne « threats »
    assert "203.0.113.9" in p.inner_text("#bMen") and "HAUTE" in p.inner_text("#bMen")
    assert "Maître élu" in p.inner_text("#t-apercu") and "a1b2c3d4e5f6a7b8" in p.inner_text("#kMaitre")
    assert err == []
    ctx.close()


def test_onglets_et_carte_du_maillage(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/p2p/", API)
    p.wait_for_selector("#bPairs tr", state="attached")
    p.click("#o-maillage")
    assert p.get_attribute("#o-maillage", "aria-selected") == "true" and p.is_visible("#t-maillage") and not p.is_visible("#t-pairs")
    assert p.locator("#carte circle").count() == 3 and "3 nœuds" in p.inner_text("#nMaillage")
    ctx.close()


def test_retirer_un_pair_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/p2p/", {**API, "/peers/gk1": (200, {"status": "ok"})})
    p.click("#o-pairs")
    p.wait_for_selector("#bPairs tr td.act")
    p.locator("#bPairs tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "DELETE"]          # pas encore : il faut confirmer
    p.locator("#bPairs tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('retiré')")
    assert ("DELETE", "/peers/gk1", None) in appels
    ctx.close()


def test_ajouter_un_pair_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/p2p/", API)
    p.click("#o-pairs"); p.click("#addPair")
    p.fill("#fPair [name=address]", "192.0.2.50:8080"); p.fill("#fPair [name=description]", "Maison")
    p.click("#fPair button[type=submit]")
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/peers"][0]
    assert json.loads(post[2]) == {"address": "192.0.2.50:8080", "peer_id": None, "description": "Maison"}
    ctx.close()


def test_service_enregistre_activation_et_demande(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/p2p/", API)
    p.click("#o-services"); p.wait_for_selector("#bServ tr td.act")
    p.get_by_text("Demander l’accès").click()
    p.wait_for_function("document.getElementById('rServ').textContent.includes('Demande')")
    assert ("POST", "/services/svc-1/request", "{}") in appels
    p.click("#addServ"); p.fill("#fServ [name=name]", "web"); p.fill("#fServ [name=port]", "8080"); p.click("#fServ button[type=submit]")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('enregistré')")
    assert json.loads([a for a in appels if a[1] == "/services" and a[0] == "POST"][0][2]) == {"name": "web", "type": "http", "port": 8080, "description": ""}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/p2p/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tPairs", "#tVivants", "#tServices", "#tRole")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/p2p/?demo=1", {})
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-pairs"); p.locator("#bPairs tr").first.get_by_text("Sonder").click()
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/p2p/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bPairs tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()

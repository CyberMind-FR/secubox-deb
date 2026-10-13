# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""WebUI panel /rlevel (task 7, #rlevel-per-peer): peer table with effective-mode
badges, admin floor/force controls, peer self-service — plus the navbar/token
conventions and the XSS-delegation guard (proxypac lesson: never interpolate
API-sourced data — pubkey, label — into an inline `onclick="..."` string).
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML_PATH = ROOT / "www" / "rlevel" / "index.html"
MENU_PATH = ROOT / "menu.d" / "27-rlevel.json"


def _html() -> str:
    return HTML_PATH.read_text()


# ── navbar / shared skin ────────────────────────────────────────────────

def test_sidebar_and_aurora_profile_present():
    html = _html()
    assert '<nav class="sidebar" id="sidebar">' in html
    assert '/shared/sidebar.js' in html
    # profil Aurora (#2552) : page autonome, plus de skin partagé ni de police distante
    assert 'hybrid-skin.css' not in html and 'hybrid-dark' not in html and 'fonts.googleapis' not in html
    assert '--fond:#060d1b' in html and 'sbxVue' in html and "onglet: 'rlevel'" in html


# ── auth token convention ────────────────────────────────────────────────

def test_uses_sbx_token_bearer_and_same_origin_credentials():
    html = _html()
    assert "sbx_token" in html
    assert "'Bearer ' +" in html or '"Bearer " +' in html
    assert "credentials:" in html and "same-origin" in html
    # must not read any other localStorage key as the token
    assert "localStorage.getItem('jwt_token')" not in html
    assert "localStorage.getItem('token')" not in html


# ── API contract (task 6) ────────────────────────────────────────────────

def test_calls_admin_peers_list():
    html = _html()
    assert "/rlevel/peers" in html


def test_calls_admin_peer_post_with_pubkey_in_body():
    html = _html()
    assert "/rlevel/peer'" in html or '/rlevel/peer"' in html
    assert "method: 'POST'" in html or 'method:"POST"' in html or "method:'POST'" in html
    # pubkey must travel in the JSON body, never interpolated into the URL
    assert "/rlevel/peer/" not in html
    assert "pubkey" in html


def test_calls_self_service_me_get_and_post():
    html = _html()
    assert "/rlevel/me" in html
    assert "chosen" in html


# ── mode badges (4 distinct) ─────────────────────────────────────────────

def test_four_mode_badges_present_and_distinctly_colored():
    html = _html()
    for mode in ("off", "passive", "active", "reel"):
        assert re.search(r'badge-' + mode + r'\b', html), f"missing badge-{mode} class"
    # pull out the 4 badge color declarations and assert they're distinct
    colors = re.findall(r'\.badge-(?:off|passive|active|reel)\s*\{[^}]*color:\s*([^;]+);', html)
    assert len(colors) >= 4
    assert len(set(colors)) == len(colors), f"badge colors not all distinct: {colors}"


# ── admin controls: floor + force/unlock ─────────────────────────────────

def test_admin_floor_and_force_controls_present():
    html = _html()
    assert "floor" in html
    assert "forced" in html
    # a control to clear/unlock a forced mode
    assert "force" in html.lower()


# ── self-service control ─────────────────────────────────────────────────

def test_self_service_chosen_control_present():
    html = _html()
    assert "rlevel/me" in html
    assert "chosen" in html


# ── XSS guard — CRITICAL (proxypac lesson) ───────────────────────────────

def test_no_inline_handler_interpolates_api_data():
    """No on*="...${...}..." handler anywhere — API-sourced values (pubkey,
    label) must never be spliced into an inline event-handler string. Row/card
    actions must use data-* attributes + a delegated listener instead."""
    html = _html()
    # On retire d'abord les commentaires (HTML + JS de ligne) pour ne pas
    # flaguer une DOC qui mentionne onclick="..." ; le (?<!:) préserve http://.
    stripped = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    stripped = re.sub(r"(?<!:)//[^\n]*", "", stripped)
    # Whitelist des SEULS handlers inline statiques autorisés (aucune donnée
    # d'API). Tout autre handler inline — interpolation `${...}` OU concaténation
    # `'`+var+`'` OU toute variable — est un offender : les actions de ligne
    # DOIVENT passer par data-* + un listener délégué. (Garde renforcé après la
    # leçon XSS proxypac : l'ancien garde ne détectait que `${`.)
    ALLOWED_STATIC = {"loadPeers()"}
    offenders = [
        m.group(0)
        for m in re.finditer(r'\son\w+\s*=\s*"([^"]*)"', stripped)
        if m.group(1).strip() not in ALLOWED_STATIC
    ]
    assert offenders == [], f"inline handler non-statique (utilise data-*+délégation): {offenders}"


def test_uses_event_delegation_with_dataset():
    html = _html()
    assert "data-pubkey" in html
    assert "dataset" in html
    assert "addEventListener('click'" in html or 'addEventListener("click"' in html


def test_esc_helper_defined_and_used():
    html = _html()
    assert "function esc(" in html
    assert "esc(" in html.split("function esc(", 1)[1]  # used somewhere after definition


# ── graceful degradation ─────────────────────────────────────────────────

def test_fetches_are_guarded_with_try_catch():
    html = _html()
    assert "try {" in html and "catch" in html


# ── menu.d entry ──────────────────────────────────────────────────────────

def test_menu_entry_valid_json_with_required_fields():
    entry = json.loads(MENU_PATH.read_text())
    assert entry["id"] == "rlevel"
    assert entry["name"]
    assert entry["path"] == "/rlevel/"
    assert entry["icon"]
    assert entry["order"] != 26  # distinct from toolbox's own entry


# ── comportement réel (#2552) : vrai navigateur, API simulée ─────────────

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PEERS = {"peers": [
    {"pubkey": "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555=", "label": "iPhone <b>x</b>", "chosen": "passive", "floor": "off", "forced": None, "effective": "passive", "live": True},
    {"pubkey": "ZZZZ9999YYYY8888XXXX7777WWWW6666VVVV5555=", "label": "Atelier", "chosen": "active", "floor": "passive", "forced": "reel", "effective": "reel", "live": False}]}
ME = {"chosen": "passive", "forced": None, "floor": "off", "effective": "passive"}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "rlevel":
            r.fulfill(status=200, content_type="text/html", body=_html())
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/toolbox", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), (200, {"status": "ok"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/toolbox/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


OK = {("GET", "/rlevel/peers"): (200, PEERS), ("GET", "/rlevel/me"): (200, ME)}


def test_tuiles_tableau_et_pas_d_injection_html(navigateur):
    ctx, p, err, _ = _ouvre(navigateur, "http://sbx.test/rlevel/", OK)
    p.wait_for_selector("#peersBody tr[data-pubkey]")
    assert [p.inner_text(i) for i in ("#tPairs", "#tLive", "#tForces", "#tReel")] == ["2", "1", "1", "1"]
    assert p.locator("#peersBody b").count() == 0          # le libellé est échappé, jamais interprété
    assert "iPhone <b>x</b>" in p.inner_text("#peersBody") and err == []
    ctx.close()


def test_appliquer_envoie_le_meme_corps_et_deverrouiller_envoie_null(navigateur):
    ctx, p, _, appels = _ouvre(navigateur, "http://sbx.test/rlevel/", OK)
    p.wait_for_selector("#peersBody tr[data-pubkey]")
    ligne = p.locator("#peersBody tr").first
    ligne.locator(".floor-sel").select_option("passive"); ligne.locator(".forced-sel").select_option("active")
    ligne.get_by_text("Appliquer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('mis à jour')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/rlevel/peer"][0]
    assert json.loads(post[2]) == {"pubkey": "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555=", "floor": "passive", "forced": "active"}
    p.locator("#peersBody tr").nth(1).get_by_text("Déverrouiller").click()
    p.wait_for_timeout(300)
    assert json.loads([a for a in appels if a[0] == "POST"][-1][2]) == {"pubkey": "ZZZZ9999YYYY8888XXXX7777WWWW6666VVVV5555=", "forced": None}
    ctx.close()


def test_libre_service_regle_chosen_et_se_verrouille_si_force(navigateur):
    ctx, p, _, appels = _ouvre(navigateur, "http://sbx.test/rlevel/", OK)
    p.wait_for_selector("#meChosenSel")
    p.select_option("#meChosenSel", "active"); p.click("#meApplyBtn")
    p.wait_for_function("document.getElementById('toast').textContent.includes('ACTIVE')")
    assert ("POST", "/rlevel/me", json.dumps({"chosen": "active"}, separators=(",", ":"))) in appels
    ctx.close()
    ctx, p, _, _ = _ouvre(navigateur, "http://sbx.test/rlevel/", {**OK, ("GET", "/rlevel/me"): (200, {**ME, "forced": "reel", "effective": "reel"})})
    p.wait_for_selector("#meCard .moi")
    assert "libre-service désactivé" in p.inner_text("#meCard") and p.locator("#meChosenSel").count() == 0
    ctx.close()


def test_sans_session_et_refus_admin(navigateur):
    ctx, p, err, _ = _ouvre(navigateur, "http://sbx.test/rlevel/", {("GET", "/rlevel/peers"): (401, {}), ("GET", "/rlevel/me"): (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and p.inner_text("#tPairs") == "—" and err == []
    ctx.close()
    ctx, p, _, _ = _ouvre(navigateur, "http://sbx.test/rlevel/", {("GET", "/rlevel/peers"): (403, {}), ("GET", "/rlevel/me"): (403, {})})
    p.wait_for_function("document.getElementById('peersBody').textContent.includes('indisponible')")
    assert p.inner_text("#tPairs") == "—" and "libre-service indisponible" in p.inner_text("#meCard")
    ctx.close()


def test_demo_inerte_et_telephone_sans_debordement(navigateur):
    ctx, p, err, appels = _ouvre(navigateur, "http://sbx.test/rlevel/?demo=1&embed=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#peersBody tr[data-pubkey]")
    assert p.is_visible("#demo") and p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.locator("#peersBody tr").first.get_by_text("Appliquer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()

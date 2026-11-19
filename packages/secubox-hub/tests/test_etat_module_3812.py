# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3812 : bouton d'état du module dans l'en-tête de chaque page, raison d'un « HORS LIGNE ».

Trois niveaux : texte du script (CSP, aucun innerHTML ni gestionnaire en ligne), logique pure sous Node,
puis deux vraies pages de module (mail, ai-gateway) dans Chromium avec le VRAI sidebar.js et une API
simulée : éveillé, endormi (réveil), en échec, dépendance endormie, anonyme, endormir (confirmation dans
le panneau), page sans module, téléphone 420 px. `SBX_CAPTURES=<dossier>` y range les captures.
"""
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

HUB = Path(__file__).resolve().parents[1]
PAQUETS = HUB.parent
JS = (HUB / "www" / "shared" / "etat-module.js").read_text(encoding="utf-8")
CSS = (HUB / "www" / "shared" / "etat-module.css").read_text(encoding="utf-8")
# Le code sans ses commentaires (qui citent innerHTML pour dire qu'il n'est pas employé).
CODE = re.sub(r"(?m)^\s*//.*$", "", re.sub(r"/\*.*?\*/", "", JS, flags=re.S))
SIDEBAR = (HUB / "www" / "shared" / "sidebar.js").read_text(encoding="utf-8")
PAGES = {
    "mail": (PAQUETS / "secubox-mail" / "www" / "mail" / "index.html").read_text(encoding="utf-8"),
    "ai-gateway": (PAQUETS / "secubox-ai-gateway" / "www" / "ai-gateway" / "index.html").read_text(encoding="utf-8"),
}


# ── Texte ─────────────────────────────────────────────────────────────────
def test_script_compatible_csp_et_sans_html_de_donnees():
    assert JS.startswith("// SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    assert CSS.startswith("/* SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    assert "innerHTML" not in CODE and "insertAdjacentHTML" not in CODE and "outerHTML" not in CODE
    assert not re.search(r"\bconfirm\(|\balert\(|\bprompt\(|\beval\(|new Function", CODE)
    assert "setAttribute('style'" not in JS and 'setAttribute("style"' not in JS
    assert "setAttribute('on" not in JS and ".onclick" not in JS
    # Mêmes routes que le backend secubox-profiles, aucune autre écriture.
    assert set(re.findall(r"API \+ '(/[a-z]+)", JS)) == {"/lifecycles", "/module"}
    assert set(re.findall(r"API \+ '/' \+ nom", JS)) and "geste('wake'" in JS and "geste('sleep'" in JS
    assert "credentials: 'same-origin'" in JS and "'sbx_token'" in JS


def test_sidebar_charge_le_script_par_la_meme_origine():
    assert "script.src = '/shared/etat-module.js'" in SIDEBAR
    assert "window.SbxEtatModule" in SIDEBAR


def test_les_routes_lues_existent_dans_secubox_profiles():
    web = (PAQUETS / "secubox-profiles" / "api" / "web.py").read_text(encoding="utf-8")
    for route in ('"/api/v1/profiles/lifecycles"', '"/api/v1/profiles/module/{mid}"',
                  '"/api/v1/profiles/wake"', '"/api/v1/profiles/sleep"'):
        assert route in web


# ── Logique pure sous Node ────────────────────────────────────────────────
NODE = shutil.which("node")


@pytest.mark.skipif(not NODE, reason="node absent")
def test_logique_pure_sous_node():
    script = r"""
const L = require(process.argv[1]);
const ok = (c, m) => { if (!c) { console.error('ÉCHEC ' + m); process.exit(1); } };
const menu = {categories: [{items: [{id: 'hub', path: '/'}, {id: 'mail', path: '/mail/'},
              {id: 'smtp-relay', path: 'https://admin.x/mail/relais/'}, {id: 'media-smb', path: '/media/smb.html'}]}]};
ok(JSON.stringify(L.candidatsModule('/mail/index.html', menu, null)) === '["mail"]', 'mail');
ok(L.candidatsModule('/mail/relais/x.html', menu, null)[0] === 'smtp-relay', 'préfixe le plus long');
ok(L.candidatsModule('/media/smb.html', menu, null)[0] === 'media-smb', 'fichier exact');
ok(L.candidatsModule('/x/', menu, 'Mauvais id')[0] === 'x', 'explicite invalide ignoré');
ok(L.candidatsModule('/x/', null, 'mail')[0] === 'mail', 'explicite prioritaire');
ok(L.candidatsModule('/', menu, null)[0] === 'hub', 'racine');
ok(L.choisirModule(['zz', 'mail'], [{id: 'mail'}]).id === 'mail', 'choix');
ok(L.choisirModule(['zz'], [{id: 'mail'}]) === null, 'aucun');
// Jamais « endormi » sans que l'API le dise.
ok(L.raisonHorsLigne(null, {id: 'm', sleep_state: 'n/a'}).texte === 'raison inconnue', 'n/a');
ok(L.raisonHorsLigne(null, {id: 'm', sleep_state: 'up'}).texte === 'raison inconnue', 'up');
ok(L.raisonHorsLigne(null, {id: 'm', sleep_state: 'asleep'}).reveiller === 'm', 'asleep');
ok(L.raisonHorsLigne({id: 'm', raison: {code: 'inconnu'}}, {id: 'm', sleep_state: 'asleep'}).texte === 'raison inconnue', 'fiche fait foi');
ok(L.raisonHorsLigne({id: 'm', raison: {code: 'echec', unite: 'u.service'}}).texte === 'en échec : u.service', 'échec');
ok(L.raisonHorsLigne({id: 'm', raison: {code: 'dependance_endormie', dependance: 'v'}}).reveiller === 'v', 'dép');
ok(L.raisonHorsLigne({id: 'm', raison: {code: 'arrete'}}).texte === 'service arrêté', 'arrêt');
ok(L.etatPastille({etat: 'eveille', etat_global: 'dependance'}) === 'dependance', 'global');
ok(L.etatPastille(null, {sleep_state: 'n/a', lifecycle: 'always-on'}) === 'permanent', 'permanent');
ok(L.motEtat('echec') === 'En échec' && L.motEtat('zz') === 'État inconnu', 'mots');
ok(L.messageRapport('sleep', {status: 'applied', changed: []}, 'm').texte.indexOf('garde m éveillé') > 0, 'no-op');
ok(L.messageRapport('wake', {status: 'woken'}, 'm').classe === 'ok', 'réveil');
ok(L.messageHttp(403) === 'Réservé aux administrateurs de la box.', '403');
"""
    r = subprocess.run([NODE, "-e", script, str(HUB / "www" / "shared" / "etat-module.js")],
                       capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 0, r.stderr


# ── Navigateur ────────────────────────────────────────────────────────────
sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"
CAPTURES = os.environ.get("SBX_CAPTURES")

MENU = {"categories": [{"name": "Services", "icon": "x", "items": [
    {"id": "mail", "name": "Messagerie", "path": "/mail/", "icon": "✉"},
    {"id": "ai-gateway", "name": "Passerelle IA", "path": "/ai-gateway/", "icon": "🤖"}]}]}


def _unite(nom, etat="actif"):
    a = {"actif": "active", "echec": "failed", "inactif": "inactive"}[etat]
    return {"unite": nom, "etat": etat, "active_state": a, "sub_state": "running" if etat == "actif" else "dead",
            "result": "exit-code" if etat == "echec" else "success"}


def _dep(i, etat, sleepable=False):
    return {"id": i, "etat": etat, "sleepable": sleepable, "connue": True, "lifecycle": "on-demand" if sleepable else "always-on",
            "sleep_state": "asleep" if etat == "endormi" else ("up" if sleepable else "n/a"), "unites": []}


def fiche(mid, etat="eveille", unites=None, deps=None, raison=None, sleep_state=None, etat_global=None):
    return {"id": mid, "lifecycle": "on-demand", "wake_class": "normal", "protected": False, "runtime": "native",
            "sleepable": True, "sleep_state": sleep_state or ("asleep" if etat == "endormi" else "up"),
            "on": "on" if etat == "eveille" else "off", "etat": etat, "etat_global": etat_global or etat,
            "unites": unites or [_unite("secubox-%s.service" % mid, "actif" if etat == "eveille" else "inactif")],
            "unites_en_echec": [], "wake_budget_s": 45.0, "dependances": deps or [],
            "raison": raison or {"code": etat}, "cached_at": "2026-11-19T10:00:00+00:00", "age_s": 1.0}


def _ouvrir(page, scenario, largeur=1400, actions=None, capture=None):
    """scenario : dict avec 'lifecycles' (liste), 'module' (callable(n_appel) -> (code, corps)),
    'wake'/'sleep' (code, corps). Rend un relevé de la page."""
    src = PAGES[page]

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:                       # noqa: BLE001 — navigateur absent : test sauté
                return ("skip", str(e))
            pg = nav.new_page(viewport={"width": largeur, "height": 900})
            erreurs, posts, n = [], [], {"module": 0}
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u, m = route.request.url, route.request.method
                code, corps = 404, {"detail": "absent"}
                if "/api/v1/profiles/lifecycles" in u:
                    code, corps = scenario.get("lifecycles_code", 200), {"lifecycles": scenario["lifecycles"]}
                elif "/api/v1/profiles/module/" in u:
                    n["module"] += 1
                    code, corps = scenario["module"](n["module"])
                elif m == "POST" and "/api/v1/profiles/" in u:
                    nom = u.rsplit("/", 1)[1]
                    posts.append((nom, json.loads(route.request.post_data or "{}")))
                    code, corps = scenario.get(nom, (200, {"status": "woken"}))
                elif "/api/v1/hub/public/menu" in u:
                    code, corps = 200, MENU
                elif "/api/v1/hub/" in u:
                    code, corps = 200, {}
                elif "/api/v1/" + page in u:
                    code, corps = 502, {"detail": "Bad Gateway"}
                route.fulfill(status=code, content_type="application/json", body=json.dumps(corps))
            pg.route("http://t.test/api/**", api)

            def statique(route):
                u = route.request.url
                nom = u.split("/shared/", 1)[1].split("?")[0]
                f = HUB / "www" / "shared" / nom
                if nom in ("sidebar.js", "etat-module.js", "etat-module.css") and f.is_file():
                    ct = "text/css" if nom.endswith(".css") else "text/javascript"
                    route.fulfill(status=200, content_type=ct, body=f.read_text(encoding="utf-8"))
                else:
                    route.fulfill(status=200, content_type="text/css" if nom.endswith(".css") else "text/javascript", body="")
            pg.route("http://t.test/shared/**", statique)
            pg.route("http://t.test/%s/**" % page, lambda r: r.fulfill(status=200, content_type="text/html", body=src))
            if scenario.get("jeton"):
                pg.add_init_script("try{localStorage.setItem('sbx_token','x.e30.y')}catch(e){}")
            pg.goto("http://t.test/%s/" % page)
            pg.wait_for_timeout(1200)
            for a in actions or []:
                if a[0] == "clic":
                    pg.click(a[1])
                elif a[0] == "attendre":
                    pg.wait_for_timeout(a[1])
            pg.wait_for_timeout(400)
            if capture and CAPTURES:
                pg.screenshot(path=str(Path(CAPTURES) / ("etat-3812-%s.png" % capture)), full_page=False)
            r = pg.evaluate("""() => {
                const env = document.querySelector('.sbx-etat');
                const raf = document.querySelector('#rafraichir');
                const pan = document.querySelector('.sbx-etat-panneau');
                const rai = [...document.querySelectorAll('.sbx-etat-raison')].filter(x => !x.hidden).map(x => x.innerText);
                const se = document.scrollingElement;
                return {
                    puce: env ? env.innerText.split('\\n')[0] : null,
                    etat: env ? env.getAttribute('data-etat') : null,
                    avantActualiser: !!(env && raf && env.nextElementSibling === raf),
                    panneau: pan && !pan.hidden ? pan.innerText : null,
                    raisons: rai,
                    badge: (document.querySelector('#etat') || {}).textContent || null,
                    debord: se.scrollWidth - se.clientWidth,
                    panDeborde: pan && !pan.hidden ? (pan.getBoundingClientRect().left < 0 || pan.getBoundingClientRect().right > document.documentElement.clientWidth) : false,
                    xss: window.xss === undefined,
                };
            }""")
            nav.close()
            return ("ok", r, erreurs, posts, n["module"])
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=120)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def _lc(mid, sleep_state="up", lifecycle="on-demand"):
    return [{"id": mid, "lifecycle": lifecycle, "sleep_state": sleep_state, "portal_domain": None}]


def _sans_erreur_du_script(erreurs):
    assert not [e for e in erreurs if "etat-module" in e or "SbxEtat" in e or "sbx-etat" in e], erreurs


@pytest.mark.parametrize("page", ["mail", "ai-gateway"])
def test_eveille_puce_avant_actualiser_et_hors_ligne_sans_sommeil_invente(page):
    r, erreurs, posts, _ = _ouvrir(page, {"lifecycles": _lc(page), "module": lambda n: (200, fiche(page))},
                                   actions=[("clic", ".sbx-etat-puce")], capture=page + "-eveille")
    _sans_erreur_du_script(erreurs)
    assert r["puce"] == "Éveillé" and r["etat"] == "eveille" and r["avantActualiser"]
    assert r["badge"] == "HORS LIGNE"
    assert r["raisons"] and "raison inconnue (module éveillé)" in r["raisons"][0] and "endormi" not in r["raisons"][0]
    assert "secubox-%s.service" % page in r["panneau"] and "Endormir" in r["panneau"]
    assert "à la demande" in r["panneau"]
    assert posts == []


def test_endormi_reveiller_depuis_la_raison_puis_relit_l_etat():
    etats = {"n": 0}

    def module(n):
        etats["n"] = n
        return (200, fiche("mail", "eveille")) if n > 1 else (200, fiche("mail", "endormi"))
    r0, *_ = _ouvrir("mail", {"lifecycles": _lc("mail", "asleep"), "module": lambda n: (200, fiche("mail", "endormi"))},
                     capture="mail-endormi")
    assert r0["puce"] == "Endormi" and r0["raisons"] and "endormi" in r0["raisons"][0] and "Réveiller" in r0["raisons"][0]
    r, erreurs, posts, appels = _ouvrir("mail", {"lifecycles": _lc("mail", "asleep"), "module": module,
                                                 "wake": (200, {"status": "woken", "module": "mail"})},
                                        actions=[("clic", ".sbx-etat-raison .sbx-etat-btn"), ("attendre", 800)],
                                        capture="mail-reveille")
    _sans_erreur_du_script(erreurs)
    assert posts == [("wake", {"module": "mail"})]
    assert appels >= 2 and r["puce"] == "Éveillé"
    assert "mail réveillé." in r["panneau"]


def test_en_echec_nomme_l_unite():
    f = fiche("mail", "echec", unites=[_unite("secubox-mail.service", "actif"), _unite("secubox-mail-sync.service", "echec")],
              raison={"code": "echec", "unite": "secubox-mail-sync.service"}, sleep_state="asleep")
    r, erreurs, _, _ = _ouvrir("mail", {"lifecycles": _lc("mail", "asleep"), "module": lambda n: (200, f)},
                               actions=[("clic", ".sbx-etat-puce")], capture="mail-echec")
    _sans_erreur_du_script(erreurs)
    assert r["puce"] == "En échec"
    assert r["raisons"][0].endswith("en échec : secubox-mail-sync.service")
    assert "endormi" not in r["raisons"][0] and "Réveiller" not in r["raisons"][0]
    assert "en échec" in r["panneau"] and "Endormir" not in r["panneau"]


def test_dependance_endormie_et_texte_hostile_inerte():
    f = fiche("ai-gateway", "eveille", deps=[_dep("vault", "eveille"), _dep(HOSTILE, "arrete"), _dep("ollama", "endormi", True)],
              raison={"code": "dependance_endormie", "dependance": "ollama"}, etat_global="dependance")
    r, erreurs, posts, _ = _ouvrir("ai-gateway", {"lifecycles": _lc("ai-gateway"), "module": lambda n: (200, f),
                                                   "wake": (200, {"status": "woken", "module": "ollama"})},
                                   actions=[("clic", ".sbx-etat-puce")], capture="ai-gateway-dependance")
    _sans_erreur_du_script(erreurs)
    assert r["puce"] == "Dépendance en panne" and r["xss"]
    assert "dépendance ollama endormie" in r["raisons"][0]
    assert HOSTILE in r["panneau"]                     # affiché comme texte, jamais interprété
    r2, _, posts2, _ = _ouvrir("ai-gateway", {"lifecycles": _lc("ai-gateway"), "module": lambda n: (200, f),
                                               "wake": (200, {"status": "woken", "module": "ollama"})},
                               actions=[("clic", ".sbx-etat-raison .sbx-etat-btn"), ("attendre", 600)])
    assert posts2 == [("wake", {"module": "ollama"})]


def test_anonyme_lecture_seule_sans_endormir():
    r, erreurs, posts, _ = _ouvrir("mail", {"lifecycles": _lc("mail", "up"), "module": lambda n: (401, {"detail": "Not authenticated"})},
                                   actions=[("clic", ".sbx-etat-puce")], capture="mail-anonyme")
    _sans_erreur_du_script(erreurs)
    assert r["puce"] == "Éveillé"
    assert "session d'administration requise" in r["panneau"]
    assert "Endormir" not in r["panneau"] and "Réveiller" not in r["panneau"]
    assert r["raisons"] and "raison inconnue" in r["raisons"][0]
    r2, *_ = _ouvrir("mail", {"lifecycles": _lc("mail", "n/a", "always-on"), "module": lambda n: (403, {})},
                     actions=[("clic", ".sbx-etat-puce")])
    assert r2["puce"] == "Permanent" and "Endormir" not in r2["panneau"] and "Réveiller" not in r2["panneau"]


def test_endormir_confirmation_dans_le_panneau():
    r, erreurs, posts, _ = _ouvrir("mail", {"lifecycles": _lc("mail"), "module": lambda n: (200, fiche("mail")),
                                            "sleep": (200, {"status": "applied", "changed": [], "failed": [], "rolled_back": []})},
                                   actions=[("clic", ".sbx-etat-puce"), ("clic", ".sbx-etat-panneau .sbx-etat-btn.danger")],
                                   capture="mail-confirmer")
    assert posts == [] and "Confirmer" in r["panneau"] and "Annuler" in r["panneau"]
    r, erreurs, posts, _ = _ouvrir("mail", {"lifecycles": _lc("mail"), "module": lambda n: (200, fiche("mail")),
                                            "sleep": (200, {"status": "applied", "changed": [], "failed": [], "rolled_back": []})},
                                   actions=[("clic", ".sbx-etat-puce"), ("clic", ".sbx-etat-panneau .sbx-etat-btn.danger"),
                                            ("clic", ".sbx-etat-panneau .sbx-etat-btn.danger"), ("attendre", 600)])
    _sans_erreur_du_script(erreurs)
    assert posts == [("sleep", {"module": "mail"})]
    assert "garde mail éveillé" in r["panneau"]


def test_refus_http_affiche_dans_le_panneau():
    r, _, posts, _ = _ouvrir("mail", {"lifecycles": _lc("mail", "asleep"), "module": lambda n: (200, fiche("mail", "endormi")),
                                      "wake": (401, {"detail": "Not authenticated"})},
                             actions=[("clic", ".sbx-etat-puce"), ("clic", ".sbx-etat-panneau .sbx-etat-btn.prim"), ("attendre", 600)])
    assert posts == [("wake", {"module": "mail"})] and "Connexion requise." in r["panneau"]


def test_page_sans_module_connu_n_affiche_rien():
    r, erreurs, _, appels = _ouvrir("mail", {"lifecycles": _lc("autre"), "module": lambda n: (200, fiche("autre"))})
    _sans_erreur_du_script(erreurs)
    assert r["puce"] is None and r["raisons"] == [] and appels == 0
    r, *_ = _ouvrir("mail", {"lifecycles": [], "lifecycles_code": 401, "module": lambda n: (200, fiche("mail"))})
    assert r["puce"] is None


@pytest.mark.parametrize("page", ["mail", "ai-gateway"])
def test_telephone_420_sans_debordement(page):
    f = fiche(page, "eveille", deps=[_dep("vault", "eveille"), _dep("ollama-tres-long-nom-de-dependance", "endormi", True)],
              raison={"code": "dependance_endormie", "dependance": "ollama-tres-long-nom-de-dependance"}, etat_global="dependance")
    r, erreurs, _, _ = _ouvrir(page, {"lifecycles": _lc(page), "module": lambda n: (200, f)}, largeur=420,
                               actions=[("clic", ".sbx-etat-puce")], capture=page + "-420")
    _sans_erreur_du_script(erreurs)
    assert r["puce"] == "Dépendance en panne"
    assert r["debord"] <= 0 and not r["panDeborde"]

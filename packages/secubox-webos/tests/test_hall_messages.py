# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: webos — messages reçus par le Hall et ses cartes Surf (#1609)

Le Hall, la carte Surf et la carte Surf & Viewer sont servis tels quels à un
Chromium headless (cache Playwright), sous leurs VRAIES origines
(https://hall.gk2.secubox.in, https://<service>.gk2.secubox.in) grâce à
l'interception réseau : ni box, ni certificat. L'API est simulée.

Règles vérifiées :
  · un message n'est suivi que depuis le cadre attendu pour son type, à
    l'origine exacte de ce cadre ; une origine opaque ("null") ne fait rien ;
  · les compteurs du surf sont des nombres, affichés en texte ;
  · une adresse reçue n'ouvre que du web (http/https) ou un chemin de la box ;
  · une diffusion refusée par la box est annoncée comme telle.

Sans Playwright ni Chromium, les tests de rendu sont sautés ; le contrôle de
syntaxe des scripts (node --check) tourne dès que node est présent.
"""

import json
import mimetypes
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlencode, urlparse

import pytest

HALL = Path(__file__).resolve().parents[1] / "www" / "hall"
ORIGINE = "https://hall.gk2.secubox.in"
BROADCAST = "/api/v1/webos/public/broadcast"

# Page émettrice : poste `m` à son parent (ou à `top`), garde ce qu'on lui
# répond, peut d'abord naviguer ailleurs (`va`) ou imbriquer un cadre.
EMET = """<!doctype html><meta charset="utf-8"><script>
window.__recus=[];
addEventListener('message',function(e){ window.__recus.push({d:e.data,o:e.origin}); });
var p=new URLSearchParams(location.search);
if(p.get('va')){ location.href=p.get('va'); }
else if(p.get('imbrique')){ var f=document.createElement('iframe'); f.src=p.get('imbrique');
  document.documentElement.appendChild(f); }
else if(p.get('m')){ setTimeout(function(){
  (p.get('cible')==='top'?top:parent).postMessage(JSON.parse(p.get('m')),'*'); }, 30); }
</script>"""


def emet(origine, message=None, **opt):
    q = {}
    if message is not None:
        q["m"] = json.dumps(message)
    q.update(opt)
    return origine + "/__emet?" + urlencode(q)


def page_emettrice(message):
    m = json.dumps(message).replace("</", "<\\/")
    return ("<!doctype html><meta charset=utf-8><script>"
            "setTimeout(function(){parent.postMessage(%s,'*');},30);</script>" % m)


class Banc:
    def __init__(self):
        self.page = None
        self.appels = []        # (méthode, chemin, corps)
        self.reponses = {}      # (méthode, chemin) -> (statut, corps JSON)
        self.documents = {}     # hôte -> HTML servi à la racine

    def servir(self, route, request):
        u = urlparse(request.url)
        self.appels.append((request.method, u.path, request.post_data))
        if u.path.startswith("/__emet"):
            return route.fulfill(status=200, content_type="text/html", body=EMET)
        if u.path.startswith("/api/"):
            statut, corps = self.reponses.get((request.method, u.path), (200, {}))
            return route.fulfill(status=statut, content_type="application/json",
                                 body=json.dumps(corps))
        if u.hostname in self.documents:
            return route.fulfill(status=200, content_type="text/html",
                                 body=self.documents[u.hostname])
        if u.hostname == "hall.gk2.secubox.in":
            chemin = u.path + ("index.html" if u.path.endswith("/") else "")
            f = (HALL / chemin.lstrip("/")).resolve()
            if HALL in f.parents and f.is_file():
                ct = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
                return route.fulfill(status=200, content_type=ct, body=f.read_bytes())
            return route.fulfill(status=404, content_type="text/plain", body="")
        return route.fulfill(status=200, content_type="text/html",
                             body="<!doctype html><title>vide</title>")

    def posts_diffusion(self):
        return [a for a in self.appels if a[0] == "POST" and a[1] == BROADCAST]

    def cadre(self, fragment):
        for f in self.page.frames:
            if fragment in f.url:
                return f
        return None

    def recus(self, fragment):
        f = self.cadre(fragment)
        return f.evaluate("window.__recus||[]") if f else None

    def pose(self, src, attrs):
        self.page.evaluate(
            """([src, attrs]) => { const f=document.createElement('iframe');
                 for (const k in attrs) f.setAttribute(k, attrs[k]);
                 f.src=src; document.body.appendChild(f); }""", [src, attrs])

    def marque(self):
        return self.page.evaluate("window.__marque")


def attend_js(cible, expr, arg=None):
    # Sondage à intervalle fixe : `raf` ne tourne pas dans un cadre hors écran.
    return cible.wait_for_function(expr, arg=arg, polling=100, timeout=10000)


def attendre(page, cond, delai=5.0):
    # page.wait_for_timeout et non time.sleep : l'API synchrone ne sert les
    # routes (donc les cadres et l'API simulée) que pendant ses propres appels.
    fin = time.time() + delai
    while time.time() < fin:
        v = cond()
        if v:
            return v
        page.wait_for_timeout(50)
    return cond()


@pytest.fixture(scope="module")
def navigateur():
    sync_api = pytest.importorskip("playwright.sync_api")
    try:
        p = sync_api.sync_playwright().start()
    except Exception as e:  # pragma: no cover - dépend du poste
        pytest.skip("Playwright indisponible : %s" % e)
    try:
        etat = {"b": p.chromium.launch()}
    except Exception as e:  # pragma: no cover - dépend du poste
        p.stop()
        pytest.skip("Chromium indisponible : %s" % e)

    # Un Chromium tombé (poste chargé) est relancé : un test n'hérite pas de
    # la panne du précédent.
    def courant():
        if not etat["b"].is_connected():
            etat["b"] = p.chromium.launch()
        return etat["b"]

    yield courant
    try:
        etat["b"].close()
    finally:
        p.stop()


@pytest.fixture
def banc(navigateur):
    ctx = navigateur().new_context(viewport={"width": 1400, "height": 1000})
    b = Banc()
    ctx.route("**/*", b.servir)
    b.page = ctx.new_page()
    yield b
    try:
        ctx.close()
    except Exception:  # pragma: no cover - navigateur déjà tombé
        pass


def ouvre_hall(b):
    b.page.goto(ORIGINE + "/", wait_until="load")
    attend_js(b.page, "typeof window.sbxExecuteAction==='function'")


# ── Syntaxe ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("nom", ["index.html", "cardlets/surf.html", "cardlets/surfviewer.html"])
def test_scripts_en_ligne_se_compilent(nom, tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    blocs = re.findall(r"<script>(.*?)</script>", (HALL / nom).read_text(), flags=re.S)
    assert blocs
    for i, bloc in enumerate(blocs):
        f = tmp_path / ("bloc%d.js" % i)
        f.write_text(bloc)
        r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, "%s bloc %d : %s" % (nom, i, r.stderr)


# ── Hall : compteurs du surf ─────────────────────────────────────────────────

def test_compteurs_surf_rendus_en_texte(banc):
    ouvre_hall(banc)
    stats = {"trackers": '<img src=x onerror="top.__marque=1">', "pubs": 3,
             "cookies": "2<b>x</b>", "notifs": 1e12, "popups": -4, "total": 10}
    banc.page.evaluate("u => { document.getElementById('surf-ov-f').src=u; }",
                       emet(ORIGINE, {"sbx": "surf-stats-up", "stats": stats}))
    attend_js(banc.page,
        "document.getElementById('surf-ov-stats').textContent.indexOf('%')>=0")
    banc.page.wait_for_timeout(300)
    z = banc.page.locator("#surf-ov-stats")
    assert z.locator("img, b b").count() == 0
    assert banc.marque() is None
    texte = z.text_content()
    assert "📢 3" in texte and "🎯 0" in texte and "🚫 0" in texte
    assert "999999" in texte and "<" not in texte


def test_compteurs_surf_ignores_hors_du_cadre_surf(banc):
    ouvre_hall(banc)
    banc.pose(emet(ORIGINE, {"sbx": "surf-stats-up", "stats": {"pubs": 7, "total": 7}}),
              {"data-micro": "surfviewer"})
    banc.page.wait_for_timeout(800)
    assert banc.page.locator("#surf-ov-stats").text_content() == ""


# ── Hall : d'où vient une diffusion ──────────────────────────────────────────

DIFFUSION = {"sbx": "diffuser", "url": "https://exemple.test/video", "titre": "t"}


@pytest.mark.parametrize("cas", ["cadre_non_pose", "cadre_imbrique",
                                 "origine_changee", "origine_opaque"])
def test_diffusion_ignoree_hors_du_cadre_attendu(banc, cas):
    ouvre_hall(banc)
    autre = "https://autre.gk2.secubox.in"
    if cas == "cadre_non_pose":
        banc.pose(emet(ORIGINE, DIFFUSION), {})
    elif cas == "cadre_imbrique":
        banc.pose(emet(ORIGINE, imbrique=emet(autre, DIFFUSION, cible="top")),
                  {"data-micro": "surfviewer"})
    elif cas == "origine_changee":
        banc.pose(emet(ORIGINE, va=emet(autre, DIFFUSION)), {"data-micro": "surfviewer"})
    else:
        banc.pose(emet(ORIGINE, DIFFUSION), {"data-micro": "surfviewer",
                                             "sandbox": "allow-scripts"})
    banc.page.wait_for_timeout(1000)
    assert banc.posts_diffusion() == []
    assert not [a for a in banc.appels if a[1] == "/api/v1/ytsas/resolve"]


@pytest.mark.parametrize("origine_carte", [ORIGINE, "https://bbs.gk2.secubox.in"])
@pytest.mark.parametrize("statut,corps,ok", [
    (200, {"actif": True, "url": "https://exemple.test/video"}, True),
    (401, {"detail": "session requise"}, False),
    (200, {"actif": False}, False),
])
def test_diffusion_depuis_une_carte_posee_et_son_resultat(banc, origine_carte, statut, corps, ok):
    banc.reponses[("POST", BROADCAST)] = (statut, corps)
    ouvre_hall(banc)
    src = emet(origine_carte, DIFFUSION)
    banc.pose(src, {"data-micro": "essai"})
    host = urlparse(origine_carte).hostname
    r = attendre(banc.page, lambda: [x for x in (banc.recus(host + "/__emet") or [])
                          if (x.get("d") or {}).get("sbx") == "diffuser-resultat"])
    assert r, "la carte n'a reçu aucun résultat"
    assert r[0]["o"] == ORIGINE
    assert r[0]["d"]["ok"] is ok
    if statut == 401:
        assert r[0]["d"]["statut"] == 401
    assert len(banc.posts_diffusion()) == 1


# ── Hall : l'action relayée par ZIA ──────────────────────────────────────────

def test_action_suivie_depuis_le_cadre_zia_seulement(banc):
    ouvre_hall(banc)
    req = {"kind": "sbx-action", "service": "hall", "action": "media.volume"}
    banc.pose(emet("https://radio.gk2.secubox.in",
                   {"sbx": "action", "req": dict(req, id="r1", params={"value": 0.9})}),
              {"data-micro": "radio"})
    banc.page.wait_for_timeout(600)
    banc.pose(emet("https://admin.gk2.secubox.in",
                   {"sbx": "action", "req": dict(req, id="z1", params={"value": 0.4})}),
              {"data-micro": "zia"})
    r = attendre(banc.page, lambda: banc.recus("admin.gk2.secubox.in/__emet"))
    assert r and r[0]["d"]["sbx"] == "sbx-action-result" and r[0]["d"]["ok"] is True
    assert r[0]["o"] == ORIGINE
    assert banc.recus("radio.gk2.secubox.in/__emet") == []
    assert banc.page.evaluate("window.dockMaitreEtat().vol") == 0.4


# ── Hall : une adresse reçue n'ouvre que du web ──────────────────────────────

def test_adresse_hors_web_jamais_ouverte_par_voir(banc):
    ouvre_hall(banc)
    u = "javascript://x/videos/embed/w/%0atop.__marque=2//"
    banc.pose(emet(ORIGINE, {"sbx": "voir", "url": u}), {"data-micro": "surfviewer"})
    banc.page.wait_for_timeout(1000)
    assert banc.marque() is None
    assert banc.page.evaluate(
        "[...document.querySelectorAll('iframe')]"
        ".filter(f=>/^\\s*javascript:/i.test(f.getAttribute('src')||'')).length") == 0


@pytest.mark.parametrize("url,attendu", [
    ("javascript:top.__marque=3", None),
    ("https://ailleurs.test/t/1", None),
    ("https://bbs.gk2.secubox.in/t/42", "https://bbs.gk2.secubox.in/t/42"),
])
def test_ouvre_hote_ne_pose_que_son_hote(banc, url, attendu):
    ouvre_hall(banc)
    banc.pose(emet(ORIGINE, {"sbx": "ouvre-hote", "hote": "bbs.gk2.secubox.in", "url": url}),
              {"data-micro": "surfviewer"})
    attend_js(banc.page, "document.querySelector('#eb-frames iframe')")
    banc.page.wait_for_timeout(500)
    srcs = banc.page.evaluate(
        "[...document.querySelectorAll('#eb-frames iframe')].map(f=>f.getAttribute('src'))")
    assert banc.marque() is None
    assert all(s.startswith("https://bbs.gk2.secubox.in/") for s in srcs), srcs
    if attendu:
        assert attendu in srcs
    else:
        assert all("?embed=1" in s for s in srcs), srcs


def test_lecteur_annonce_ailleurs_que_sa_carte_refuse(banc):
    ouvre_hall(banc)
    media = {"sbx": "media", "id": "radio", "joue": True, "zoomable": True,
             "titre": "R", "lecteur": "javascript:top.__marque=5"}
    banc.pose(emet("https://radio.gk2.secubox.in", media), {"data-micro": "radio"})
    attend_js(banc.page, "document.querySelector('#pastilles .fpast[data-id=\"radio\"]')")
    banc.page.evaluate("document.querySelector('#pastilles .fpast[data-id=\"radio\"]').click()")
    banc.page.wait_for_timeout(600)
    assert banc.marque() is None
    assert banc.page.evaluate(
        "[...document.querySelectorAll('#viewer-media iframe')]"
        ".filter(f=>!/^https:/.test(f.getAttribute('src')||'')).length") == 0


# ── Hall : la nav poussée par le service embarqué ────────────────────────────

def test_contexte_du_service_embarque_seulement_et_en_texte(banc):
    ouvre_hall(banc)
    banc.page.evaluate("openService('metanews','embed')")
    items = [{"cle": "a", "label": "<b>A</b>", "badge": "<i>3</i>",
              "icon": '<img src=x onerror="top.__marque=4">'}]
    msg = {"sbx": "contexte", "id": "metanews", "titre": "Sources", "items": items}
    metanews = "https://metanews.gk2.secubox.in"
    banc.pose(emet(metanews, msg), {"data-micro": "metanews"})
    banc.page.wait_for_timeout(800)
    assert banc.page.locator("#ctx [data-ctxpush]").count() == 0
    banc.page.evaluate("u => { document.querySelector('#eb-frames iframe').src=u; }",
                       emet(metanews, msg))
    attend_js(banc.page, "document.querySelector('#ctx [data-ctxpush]')")
    banc.page.wait_for_timeout(300)
    assert banc.page.locator("#ctx img, #ctx b, #ctx i").count() == 0
    assert banc.marque() is None
    assert "<img" in banc.page.locator("#ctx").text_content()


# ── Carte Surf ───────────────────────────────────────────────────────────────

SURF = ORIGINE + "/cardlets/surf.html?u=exemple.fr"
RELAIS = "surf-exemple-fr.gk2.secubox.in"


def test_surf_compteurs_du_relais_en_nombres(banc):
    banc.documents[RELAIS] = page_emettrice({"sbx": "surf-stats", "stats": {
        "trackers": '<img src=x onerror="top.__marque=6">', "pubs": 2,
        "tiers": "<b>1</b>", "total": 4}})
    banc.page.goto(SURF)
    attend_js(banc.page, "!document.getElementById('stats').classList.contains('hidden')")
    banc.page.wait_for_timeout(300)
    assert banc.page.locator("#stats img, #stats b b").count() == 0
    assert banc.marque() is None
    texte = banc.page.locator("#stats").text_content()
    assert "📢 2" in texte and "🎯 0" in texte and "🧩 0" in texte


@pytest.mark.parametrize("cas", ["autre_cadre", "relais_parti_hors_box"])
def test_surf_ignore_les_compteurs_hors_de_son_relais(banc, cas):
    stats = {"sbx": "surf-stats", "stats": {"pubs": 5, "total": 5}}
    if cas == "relais_parti_hors_box":
        banc.documents[RELAIS] = ("<!doctype html><script>location.href=%s;</script>"
                                  % json.dumps(emet("https://hors-box.test", stats)))
    banc.page.goto(SURF)
    if cas == "autre_cadre":
        banc.page.evaluate("u=>{const f=document.createElement('iframe'); f.src=u;"
                           " document.body.appendChild(f);}",
                           emet("https://surf-autre-fr.gk2.secubox.in", stats))
    banc.page.wait_for_timeout(1000)
    assert "hidden" in (banc.page.get_attribute("#stats", "class") or "")


@pytest.mark.parametrize("statut,corps,texte", [
    (200, {"actif": True, "url": "https://exemple.fr/"}, "diffusé au parc"),
    (401, {"detail": "session requise"}, "Réservé aux personnes connectées"),
    (403, {"detail": "interdit"}, "Réservé aux personnes connectées"),
    (200, {"actif": False}, "Diffusion impossible"),
    (500, {}, "Diffusion impossible"),
])
def test_surf_annonce_le_sort_de_la_diffusion(banc, statut, corps, texte):
    banc.reponses[("POST", BROADCAST)] = (statut, corps)
    banc.page.goto(SURF)
    banc.page.click("#diff")
    attend_js(banc.page,
        "t => document.getElementById('etat').textContent.indexOf(t)>=0", arg=texte)


# ── Carte Surf & Viewer ──────────────────────────────────────────────────────

@pytest.mark.parametrize("statut,corps,texte", [
    (401, {"detail": "session requise"}, "Réservé aux personnes connectées"),
    (200, {"actif": True, "url": "https://exemple.fr/v.mp4"}, "proposé au parc"),
])
def test_proposition_annoncee_selon_la_reponse(banc, statut, corps, texte):
    banc.reponses[("POST", BROADCAST)] = (statut, corps)
    banc.page.add_init_script(
        "try{ if(location.origin==='https://hall.gk2.secubox.in')"
        " localStorage.setItem('sbx.broadcast.hist', JSON.stringify("
        "[{u:'https://exemple.fr/v.mp4', titre:'Essai', n:1, t:Date.now()}])); }catch(e){}")
    ouvre_hall(banc)
    banc.page.evaluate(
        "document.querySelector('iframe[data-micro=\"surfviewer\"]').scrollIntoView()")
    carte = attendre(banc.page, lambda: (lambda f: f if f and f.evaluate(
        "!!document.querySelector('[data-act=diffuse]')") else None)(
        banc.cadre("/cardlets/surfviewer.html")), 8.0)
    assert carte, "carte Surf & Viewer non chargée"
    carte.evaluate("document.querySelector('[data-act=diffuse]').click()")
    attend_js(carte,
        "t => document.querySelector('[data-act=diffuse]').textContent.indexOf(t)>=0",
        arg=texte)


# ── Carte cumulative : ne relaie que sa carte embarquée ──────────────────────

CUMUL = ORIGINE + "/cardlets/cumul.html?groupe=contenu&embed=1"


@pytest.mark.parametrize("depuis,relaye", [("carte_embarquee", True), ("autre_cadre", False)])
def test_cumul_relaie_seulement_sa_carte_embarquee(banc, depuis, relaye):
    ouvre_hall(banc)
    banc.pose(CUMUL, {"data-micro": "cumul"})
    cumul = attendre(banc.page, lambda: (lambda f: f if f and f.evaluate(
        "!!document.querySelector('#corps iframe')") else None)(
        banc.cadre("/cardlets/cumul.html")), 8.0)
    assert cumul, "carte cumulative non chargée"
    src = emet(ORIGINE, {"sbx": "surf", "url": "https://exemple.test/"})
    if depuis == "carte_embarquee":
        cumul.evaluate("u => { document.querySelector('#corps iframe').src=u; }", src)
    else:
        cumul.evaluate("u => { const f=document.createElement('iframe'); f.src=u;"
                       " document.body.appendChild(f); }", src)
    ouvert = attendre(banc.page, lambda: "exemple.test" in (
        banc.page.get_attribute("#surf-ov-f", "src") or ""), 2.0)
    assert ouvert is relaye

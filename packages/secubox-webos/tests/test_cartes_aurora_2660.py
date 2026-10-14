# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2660 — cartes du Hall au profil Aurora : radar, surf, surfviewer, voicestudio, voicestudio-admin, zigbee, et le relais de session.

Statique (chaque carte) puis vrai navigateur, API simulée sur http://sbx.test. Modèle : test_ytflux_aurora_2638.py."""
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL = PKG / "www" / "hall"
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")

CARTES = ["radar", "surf", "surfviewer", "voicestudio", "voicestudio-admin", "zigbee"]
SRC = {n: (HALL / "cardlets" / f"{n}.html").read_text(encoding="utf-8") for n in CARTES}
RELAIS = (HALL / "relais.html").read_text(encoding="utf-8")

# scripts externes admis par carte (même origine, contrat du Hall) : la sonde, plus ce que la carte chargeait déjà
SCRIPTS = {
    "radar": ["../sonde.js"],
    "surf": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
    "surfviewer": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
    "voicestudio": ["../sonde.js"],
    "voicestudio-admin": ["../sonde.js"],
    "zigbee": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
}
INTERDITS = ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick=",
             "srcdoc", "javascript:")


def sans_commentaires(s):
    return re.sub(r"<!--.*?-->", "", s, flags=re.S)


# ───────────────────────── statique : chaque carte ─────────────────────────

@pytest.mark.parametrize("nom", CARTES)
def test_carte_aurora_autonome_sans_dialogue_natif_ni_html_construit(nom):
    s = SRC[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s and "Aurora" in s
    assert re.findall(r'<script src="([^"]+)"', s) == SCRIPTS[nom]
    assert "<link" not in s                                          # ni spicy.css ni slicebar.css : la page est autonome
    assert "--fond:#060d1b" in s and "container-type:inline-size" in s and "container-name:a" in s
    assert "data-theme" not in s and "prefers-color-scheme" not in s    # thème unique sombre
    for interdit in INTERDITS:
        assert interdit not in s, interdit
    assert "lorem" not in s.lower()
    assert "demo" in s and "textContent" in s
    assert not re.search(r"Math\.random", s)                          # aucune série inventée


@pytest.mark.parametrize("nom", [c for c in CARTES if c != "surf"])
def test_carte_annonce_sa_hauteur_par_son_cadre(nom):
    s = SRC[nom]
    assert "sbxVue" in s and f"var ONGLET = '{nom}'" in s and "onglet: ONGLET" in s
    assert "document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY" in s
    assert "documentElement.scrollHeight" not in s and "100vh" not in s
    assert "ResizeObserver" in s and "location.origin" in s
    assert "embed" in s


def test_surf_remplit_sa_fenetre_et_n_annonce_aucune_hauteur():
    s = SRC["surf"]
    assert "sbxVue" not in s and "ResizeObserver" not in s            # un navigateur, pas un tableau de bord
    assert "embed" in s


# ───────────────────────── statique : contrat de chaque carte, à l'identique ─────────────────────────

def test_radar_meme_api_lecture_seule():
    s = SRC["radar"]
    assert "/api/v1/acces/session/etat" in s and "jget('/api/v1/actor/radar?limit=30')" in s
    assert s.index("sessionOk().then") < s.index("jget('/api/v1/actor/radar")        # jamais à vide : sonde.js fermerait la carte
    assert "method" not in s and "POST" not in s and "DELETE" not in s                 # le moteur propose, la vue n'applique rien
    for zone in ("Agir", "Confirmer", "Surveiller", "Ignorer", "OBSERVE", "MITIGATE", "BLOCK"):
        assert zone in s
    assert "namespaceURI" in s and not re.search(r"https?://", sans_commentaires(s))   # l'espace de noms SVG vient du document


def test_surf_protocole_sandbox_et_liste_identiques():
    s = SRC["surf"]
    # la sandbox de l'iframe, mot pour mot, sans allow-top-navigation
    assert "'allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-popups-to-escape-sandbox'" in s
    ligne = re.search(r"setAttribute\('sandbox'[^\n]*", s).group(0)
    assert "allow-top-navigation" not in ligne and "allow-popups'" not in ligne           # popups seulement « pour s'échapper de la sandbox »
    assert "setAttribute('allow', 'fullscreen')" in s and "setAttribute('referrerpolicy', 'no-referrer')" in s
    assert s.index("setAttribute('sandbox'") < s.index("setAttribute('src', n.surf)")      # la sandbox précède l'adresse
    # messages vers le Hall (à SON origine seulement) et messages écoutés
    for m in ("surf-hote", "surf-catch", "surf-close", "surf-vide", "broadcast-on"):
        assert re.search(r"sbx: '%s'" % m, s), m
    for m in ("surf-stats", "surf-nav", "surf-back"):
        assert f"d.sbx === '{m}'" in s, m
    assert "var HALL = location.origin;" in s and not re.search(r"postMessage\([^;]*'\*'", s)
    # sûreté : relais reconnu par sa fenêtre ET son origine surf-…, ordres du seul Hall, ouverture en onglet sans opener
    assert "ev.source !== f.contentWindow" in s and "o.protocol === 'https:' && estSurf(o.hostname)" in s
    assert "ev.source === parent && ev.origin === HALL" in s
    assert "window.open(courant.surf, '_blank', 'noopener')" in s
    assert "/api/v1/webos/public/broadcast'" in s and "j.actif === true" in s
    # la règle d'aplatissement de l'origine du relais n'a pas bougé
    assert "replace(/-/g, '--').replace(/\\./g, '-')" in s and "'surf-0' + mo[1]" in s
    assert "estSurf" in s and "securitypolicyviolation" in s


def test_surf_nginx_inchange_la_csp_dediee_existe_toujours():
    assert VHOST.index("location = /cardlets/surf.html {") < VHOST.index("location /cardlets/ {")
    assert "frame-src 'self' https://*.gk2.secubox.in $sbx_cadres_box" in VHOST


def test_surfviewer_memes_messages_et_memes_appels():
    s = SRC["surfviewer"]
    for m in ("post({sbx:'diffuser', url:u, titre:titre})", "post({sbx:'voir', url:u, titre:titre})", "post({sbx:'voir', url:u})"):
        assert m in s, m
    assert "d.sbx!=='diffuser-resultat' || ev.source!==parent || ev.origin!==location.origin" in s
    assert "parent.postMessage(m, location.origin)" in s
    for u in ("'/pt/api/v1/videos/'", "'/api/v1/ytsas/list'", "'/api/v1/ytsas/title?url='", "'/api/v1/webos/public/broadcasts'",
              "'/api/v1/webos/public/broadcast/like'"):
        assert u in s, u
    for k in ("sbx_favoris", "sbx.viewer.hist", "sbx.broadcast.hist", "sbx.titres"):
        assert k in s, k
    assert "SBX_DOMAINE.partageable(u)" in s


def test_voicestudio_memes_routes_et_garde_du_micro():
    s = SRC["voicestudio"]
    assert set(re.findall(r"api\('(/[a-z]+)'", s)) == {"/etat", "/dire", "/transcrire"}
    assert "var API = '/api/v1/voicestudio/usager';" in s
    assert "JSON.stringify({texte:t, format:'mp3'})" in s and "fd.append('fichier', blob, nom); fd.append('langue', 'fr');" in s
    assert s.count("getUserMedia") == 1 and "$('b-mic').addEventListener('click', micro)" in s
    assert "autoplay" not in s and "autofocus" not in s and 'type="password"' not in s
    # la démonstration coupe AVANT toute écriture et avant le micro
    assert re.search(r"function dire\(\)\{\s*if \(DEMO\)", s) and re.search(r"function micro\(\)\{\s*var b = \$\('b-mic'\);\s*if \(DEMO\)", s)
    assert not re.search(r"https?://", sans_commentaires(s))


def test_voicestudio_admin_lecture_seule_et_rien_que_l_etat():
    s = sans_commentaires(SRC["voicestudio-admin"])
    assert set(re.findall(r"fetch\('(/api/v1/voicestudio/[a-z/]+)'", s)) == {"/api/v1/voicestudio/status"}
    assert "method:" not in s and "POST" not in s
    for secret in ("api_key", "Bearer", "10.100.", "commit"):
        assert secret not in s, secret
    for etat in ("répond", "dort", "muet", "à installer", "injoignable", "Réservé aux administrateurs", "r.status === 502"):
        assert etat in s, etat


def test_zigbee_meme_commande_toggle_et_meme_message_vers_le_hall():
    s = SRC["zigbee"]
    assert "fetch('/api/v1/zigbee' + chemin, opts)" in s and "api('/devices')" in s
    assert "'/devices/' + encodeURIComponent(nom) + '/set'" in s and "JSON.stringify({ etat: 'TOGGLE' })" in s
    assert "parent.postMessage({ sbx: 'ouvre', id: 'zigbee', url: a.href }, '*')" in s
    assert "if (DEMO) { inerte(); return; }" in s
    assert 'href="https://zigbee.gk2.secubox.in/"' in s


def test_relais_meme_liste_close_meme_fragment_et_aucune_page_construite():
    s = RELAIS
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s and "--fond:#060d1b" in s
    assert "data-theme" not in s and "prefers-color-scheme" not in s
    assert re.findall(r'<script src="([^"]+)"', s) == ["/api/v1/webos/public/hotes.js", "domaine.js"]
    for interdit in INTERDITS:
        assert interdit not in s, interdit
    assert "var RETOURS = SBX_DOMAINE.retours;" in s and "RETOURS.indexOf(origine) < 0" in s
    assert "fetch('/api/v1/webos/jeton', { method: 'POST'" in s
    assert "location.replace(retour.split('#')[0] + '#sbx=' + encodeURIComponent(j))" in s
    assert "demo" not in sans_commentaires(s).lower()                  # un relais « de démonstration » serait une redirection de plus


# ───────────────────────── vrai navigateur ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")

DOMAINE = ("window.SBX_DOMAINE={hote:function(s){return s;},partageable:function(u){return /^https?:/.test(u)?u:'https://hall.sbx.test'+u;},"
           "admin:'https://admin.sbx.test',retours:['https://hall.sbx.test'],hall:'https://hall.sbx.test'};")
HOTE = ("<!doctype html><meta charset=utf-8><style>html,body{margin:0}iframe{display:block;border:0;width:100%%;height:%dpx}</style>"
        "<iframe id=c src='%s'></iframe><script>window.__msgs=[];addEventListener('message',function(e){__msgs.push({d:e.data,o:e.origin});});</script>")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, nom, query="", api=None, taille=None, hote=False, init=None, relais=False):
    """Ouvre une carte (ou le relais) sur http://sbx.test. hote=True : dans un cadre d'une page hôte, qui note les messages reçus.
    api(methode, chemin, corps) -> (statut, objet) | None. Renvoie ctx, cible (page ou cadre), page, erreurs, appels."""
    taille = taille or {"width": 1400, "height": 900}
    ctx = navigateur.new_context(viewport=taille)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))
    if init:
        p.add_init_script(init)
    chemin_page = "/relais.html" if relais else f"/cardlets/{nom}.html"
    source = RELAIS if relais else SRC[nom]

    def fichier(r, *_):
        chemin = "/" + r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == chemin_page:
            r.fulfill(status=200, content_type="text/html", body=source)
        elif chemin == "/hote.html":
            r.fulfill(status=200, content_type="text/html", body=HOTE % (taille["height"], chemin_page + query))
        elif chemin in ("/sonde.js", "/aide.js", "/api/v1/webos/public/hotes.js"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin in ("/domaine.js", "/cardlets/../domaine.js"):
            r.fulfill(status=200, content_type="application/javascript", body=DOMAINE)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def appel(r, *_):
        chemin = r.request.url.split("http://sbx.test", 1)[1]
        if chemin == "/api/v1/webos/public/hotes.js":
            return r.fulfill(status=200, content_type="application/javascript", body="")
        appels.append((r.request.method, chemin, r.request.post_data))
        rep = api(r.request.method, chemin, r.request.post_data) if api else None
        statut, corps = rep if rep else (404, {})
        if isinstance(corps, bytes):
            r.fulfill(status=statut, content_type="audio/mpeg", body=corps)
        else:
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", appel)
    p.route("http://sbx.test/pt/**", appel)
    # les origines de relais surf et le retour du relais de session : des pages blanches
    for h in ("https://surf-exemple-fr.gk2.secubox.in/**", "https://hall.sbx.test/**", "https://admin.sbx.test/**"):
        p.route(h, lambda r, *_: r.fulfill(status=200, content_type="text/html", body="<!doctype html><title>x</title>"))
    if hote:
        p.goto("http://sbx.test/hote.html")
        cible = p.wait_for_selector("#c").content_frame()
        cible.wait_for_load_state("domcontentloaded")
    else:
        p.goto("http://sbx.test" + chemin_page + query)
        cible = p
    return ctx, cible, p, erreurs, appels


def sans_debordement(cible):
    return cible.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def hauteur_annoncee(p, cible, onglet):
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbxVue)")
    m = [x for x in p.evaluate("__msgs") if x["d"] and x["d"].get("sbxVue")][-1]
    assert m["d"]["onglet"] == onglet and m["o"] == "http://sbx.test" and 40 <= m["d"]["sbxVue"] <= 4000
    h = cible.evaluate("Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY)")
    assert abs(m["d"]["sbxVue"] - h) <= 2, (m["d"]["sbxVue"], h)


T420 = {"width": 420, "height": 800}
NOW = int(time.time())

# ── radar ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

RADAR = {"genere_le": NOW, "politique": "v2", "acteurs": [
    {"id": "ACT-0001", "niveau": "MITIGATE", "action_proposee": "mesure réversible", "capteurs": ["waf"], "evenements": 7,
     "risque": {"valeur": 82, "facteurs": [{"libelle": "balayage de ports", "points": 20}]},
     "confiance": {"valeur": 40, "facteurs": [{"libelle": "événements observés", "points": 25}]},
     "refus": ["BLOCK refusé : un seul capteur (2 requis)"], "mesure": {"niveau": "DELAI", "reste_s": 1800},
     "etapes": [{"libelle": "balayage", "evenements": 3, "capteurs": ["waf"]}]},
    {"id": "<img src=x onerror=window.__pwn=1>", "niveau": "BLOCK", "capteurs": [], "evenements": 1,
     "risque": {"valeur": 91, "facteurs": []}, "confiance": {"valeur": 90, "facteurs": []}, "etapes": []}]}


def api_radar(session=True, radar=RADAR):
    def f(m, c, _):
        if c.endswith("/acces/session/etat"):
            return 200, {"session": session}
        if "/actor/radar" in c:
            return (200, radar) if radar is not None else (503, {})
    return f


def test_radar_420_acteurs_plan_et_fiche_sans_debordement(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "radar", api=api_radar(), taille=T420)
    p.wait_for_selector("#liste .acteur")
    assert p.locator("#liste .acteur").count() == 2 and p.locator("#radar circle.pt").count() == 2
    assert sans_debordement(p) and p.evaluate("window.__pwn") is None
    assert p.locator("#liste img, #fiche img").count() == 0
    p.locator("#liste .acteur").first.click()
    t = p.inner_text("#fiche")
    for attendu in ("MITIGATE", "balayage de ports", "+20", "événements observés", "BLOCK refusé : un seul capteur", "encore 30 min"):
        assert attendu in t, attendu
    assert [a[1] for a in appels] == ["/api/v1/acces/session/etat", "/api/v1/actor/radar?limit=30"] and all(a[0] == "GET" for a in appels)
    assert p.inner_text("#tActeurs") == "2" and p.inner_text("#tBloc") == "1" and p.inner_text("#tMesures") == "1" and p.inner_text("#tRisque") == "91"
    assert err == []
    ctx.close()


def test_radar_sans_session_tirets_et_bandeau(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "radar", api=api_radar(session=False), taille=T420)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tActeurs", "#tBloc", "#tMesures", "#tRisque")] == ["—"] * 4
    assert "Ouvre une session" in p.inner_text("#liste") and p.locator("#liste .acteur").count() == 0
    assert not any("actor/radar" in a[1] for a in appels) and sans_debordement(p) and err == []
    ctx.close()


def test_radar_moteur_absent_est_dit_pas_zero(navigateur):
    ctx, p, _, err, _ = ouvre(navigateur, "radar", api=api_radar(radar=None))
    p.wait_for_selector("#liste .vide")
    assert "en démarrage ou injoignable" in p.inner_text("#liste") and p.inner_text("#etat") == "HORS LIGNE"
    assert p.inner_text("#tActeurs") == "—" and p.inner_text("#tRisque") == "—" and err == []
    ctx.close()


def test_radar_demo_annoncee_aucune_requete_et_embed_hauteur(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "radar", "?demo=1", taille=T420)
    p.wait_for_selector("#liste .acteur")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and appels == [] and sans_debordement(p)
    ctx.close()
    ctx, c, p, err, appels = ouvre(navigateur, "radar", "?demo=1&embed=1", taille={"width": 700, "height": 600}, hote=True)
    c.wait_for_selector("#liste .acteur")
    assert not c.is_visible("#tuiles") and not c.is_visible(".marque")
    hauteur_annoncee(p, c, "radar")
    assert appels == [] and err == []
    ctx.close()


# ── surf ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

SANDBOX = "allow-scripts allow-same-origin allow-forms allow-downloads allow-modals allow-popups-to-escape-sandbox"


def test_surf_420_accueil_sans_debordement_puis_cadre_a_la_sandbox_exacte(navigateur):
    ctx, p, _, err, _ = ouvre(navigateur, "surf", taille=T420)
    assert p.is_visible("#accueil") and sans_debordement(p)
    p.fill("#adr", "exemple.fr")
    p.click("#go")
    p.wait_for_selector("#vue iframe")
    f = p.locator("#vue iframe")
    assert f.count() == 1 and f.get_attribute("sandbox") == SANDBOX and f.get_attribute("src") == "https://surf-exemple-fr.gk2.secubox.in/"
    assert f.get_attribute("referrerpolicy") == "no-referrer" and f.get_attribute("allow") == "fullscreen" and f.get_attribute("title") == "Surf"
    assert not p.is_visible("#accueil") and "exemple.fr — relayé" in p.inner_text("#etat")
    assert sans_debordement(p)
    # une seconde adresse REMPLACE le cadre (jamais deux), l'accueil revient sans erreur et le cadre disparaît
    p.fill("#adr", "exemple.fr/page")
    p.click("#go")
    assert p.locator("#vue iframe").count() == 1
    p.click("#home")
    assert p.locator("#vue iframe").count() == 0 and p.is_visible("#accueil") and p.is_hidden("#home")
    assert err == []
    ctx.close()


def test_surf_dans_le_hall_protocole_hote_diffusion_et_ordre_de_recul(navigateur):
    def api(m, c, corps):
        if m == "POST" and c == "/api/v1/webos/public/broadcast":
            return 200, {"actif": True, "url": "https://exemple.fr/"}
    ctx, c, p, err, appels = ouvre(navigateur, "surf", "?u=exemple.fr&chrome=hall", api=api, taille=T420, hote=True)
    c.wait_for_selector("#vue iframe")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'surf-hote')")
    assert {"d": {"sbx": "surf-hote", "hote": "exemple.fr"}, "o": "http://sbx.test"} in p.evaluate("__msgs")
    assert c.is_visible("#fermer")
    c.click("#fermer")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'surf-close')")
    c.click("#diff")
    c.wait_for_function("document.getElementById('etat').textContent.indexOf('diffusé au parc') >= 0")
    post = [a for a in appels if a[0] == "POST"][0]
    assert json.loads(post[2])["url"] == "https://exemple.fr/"
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'broadcast-on')")
    # le Hall (la page hôte) demande de reculer : plus d'historique -> « surf-vide »
    p.evaluate("document.getElementById('c').contentWindow.postMessage({sbx:'surf-back'}, location.origin)")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'surf-vide')")
    # un ordre venu d'un autre émetteur que le Hall est ignoré : aucune hauteur n'est jamais annoncée
    assert not [m for m in p.evaluate("__msgs") if m["d"] and "sbxVue" in m["d"]]
    assert err == []
    ctx.close()


def test_surf_demo_n_ouvre_rien_ne_diffuse_rien_et_dit_les_compteurs_fictifs(navigateur):
    ctx, c, p, err, appels = ouvre(navigateur, "surf", "?demo=1&u=exemple.fr&chrome=hall", taille=T420, hote=True)
    assert c.is_visible("#demo") and "DÉMONSTRATION" in c.inner_text("#demo")
    assert c.locator("#vue iframe").count() == 0                      # ?u= ignoré en démonstration
    assert not c.locator("#stats").evaluate("e => e.classList.contains('hidden')") and "🛡️" in c.inner_text("#stats")
    c.fill("#adr", "exemple.fr")
    c.click("#go")
    assert "inerte" in c.inner_text("#etat") and c.locator("#vue iframe").count() == 0
    c.click("#fermer")
    p.wait_for_timeout(300)
    assert [m for m in p.evaluate("__msgs") if m["d"] and "sbx" in m["d"]] == []
    assert appels == [] and err == []
    ctx.close()


# ── surfviewer ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

URL_FAV = "https://video.exemple.test/w/abc123"
HOSTILE = "<img src=x onerror=window.__pwn=1>"
STOCKAGE = ("try{localStorage.setItem('sbx_favoris', JSON.stringify(['%s']));"
            "localStorage.setItem('sbx.broadcast.hist', JSON.stringify([{u:'https://exemple.test/v.mp4',titre:'%s',n:3,t:1}]));"
            "localStorage.setItem('sbx.viewer.hist', JSON.stringify([{u:'https://exemple.test/page',t:1}]));}catch(e){}" % (URL_FAV, HOSTILE))


def api_viewer(m, c, corps):
    if c.startswith("/api/v1/webos/public/broadcasts"):
        return 200, {"total": 2, "tops": [{"url": "https://exemple.test/top", "titre": "Le top du parc", "likes": 4}], "recents": []}
    if c.startswith("/api/v1/webos/public/broadcast/like"):
        return 401, {}
    if c.startswith("/api/v1/ytsas/list"):
        return 200, {"items": []}


def test_surfviewer_420_listes_du_stockage_texte_seul_et_messages_vers_le_hall(navigateur):
    ctx, c, p, err, appels = ouvre(navigateur, "surfviewer", api=api_viewer, taille=T420, hote=True, init=STOCKAGE)
    c.wait_for_selector("#st-fav .chip")
    assert c.inner_text("#c-fav") == "1" and c.inner_text("#c-diff") == "1" and c.inner_text("#c-hist") == "1" and c.inner_text("#tot") == "3 items"
    assert c.locator("#onglets [role=tab]").count() == 4 and c.get_attribute("#o-fav", "aria-selected") == "true"
    assert sans_debordement(c)
    # un titre hostile reste du texte
    c.click("#o-diff")
    c.wait_for_selector("#s-diff.actif [data-act=diffuse]")
    assert c.evaluate("window.__pwn") is None and c.locator("#st-diff img").count() == 0
    assert HOSTILE in c.inner_text("#st-diff") and "×3" in c.inner_text("#st-diff")
    # voir : message au Hall, à son origine
    c.click("#o-fav")
    c.click("#st-fav [data-act=view]")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'voir')")
    assert {"d": {"sbx": "voir", "url": URL_FAV, "titre": ""}, "o": "http://sbx.test"} in p.evaluate("__msgs")
    # proposer au parc : message, puis verdict venu du Hall (jamais annoncé d'avance)
    c.click("#o-diff")
    c.click("#st-diff [data-act=diffuse]")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'diffuser')")
    assert "proposition…" in c.inner_text("#st-diff")
    p.evaluate("document.getElementById('c').contentWindow.postMessage({sbx:'diffuser-resultat', url:'https://exemple.test/v.mp4', ok:true}, location.origin)")
    c.wait_for_function("document.querySelector('[data-act=diffuse]').textContent.indexOf('proposé au parc') >= 0")
    # coller un lien
    c.fill("#pu", "exemple.test/coller")
    c.press("#pu", "Enter")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'voir' && m.d.url === 'https://exemple.test/coller')")
    # global : la route de lecture, le ♥ refusé est dit
    c.click("#o-global")
    c.wait_for_selector("#st-global .chip")
    assert "Le top du parc" in c.inner_text("#st-global") and c.inner_text("#tGlobal") == "2"
    c.click("#st-global [data-like]")
    c.wait_for_function("document.querySelector('[data-like]').textContent === '🔒'")
    assert ("POST", "/api/v1/webos/public/broadcast/like", json.dumps({"url": "https://exemple.test/top"}, separators=(",", ":"))) in appels
    assert err == []
    ctx.close()


def test_surfviewer_vide_dit_rien_et_garde_les_zeros_reels(navigateur):
    ctx, c, p, err, _ = ouvre(navigateur, "surfviewer", api=api_viewer, taille=T420)
    c.wait_for_selector("#vide:not([hidden])")
    assert "Rien encore" in c.inner_text("#vide") and c.inner_text("#tot") == "VIDE" and c.inner_text("#tFav") == "0" and c.inner_text("#tGlobal") == "—"
    assert err == []
    ctx.close()


def test_surfviewer_demo_ne_lit_ni_n_ecrit_ni_ne_parle_au_hall(navigateur):
    ctx, c, p, err, appels = ouvre(navigateur, "surfviewer", "?demo=1", api=api_viewer, taille=T420, hote=True, init=STOCKAGE)
    c.wait_for_selector("#st-fav .chip")
    assert c.is_visible("#demo") and "DÉMONSTRATION" in c.inner_text("#demo")
    assert HOSTILE not in c.inner_text("body")                         # le stockage réel n'est pas lu
    c.click("#st-fav [data-act=view]")
    c.click("#o-diff")
    c.click("#st-diff [data-act=diffuse]")
    c.click("#o-global")
    c.wait_for_selector("#st-global .chip")
    c.click("#st-global [data-like]")
    c.fill("#pu", "exemple.test/x")
    c.press("#pu", "Enter")
    assert "inerte" in c.inner_text("#retour")
    p.wait_for_timeout(250)
    assert [m for m in p.evaluate("__msgs") if m["d"] and "sbx" in m["d"]] == []
    assert appels == [] and err == []
    assert json.loads(c.evaluate("localStorage.getItem('sbx_favoris')")) == [URL_FAV]        # intact
    ctx.close()


def test_surfviewer_embed_hauteur_annoncee(navigateur):
    ctx, c, p, err, _ = ouvre(navigateur, "surfviewer", "?embed=1", api=api_viewer, taille={"width": 700, "height": 600}, hote=True, init=STOCKAGE)
    c.wait_for_selector("#st-fav .chip")
    assert not c.is_visible("#tuiles") and not c.is_visible(".marque")
    hauteur_annoncee(p, c, "surfviewer")
    assert err == []
    ctx.close()


# ── voicestudio ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

ETAT_OK = {"disponible": True, "limites": {"texte_max": 1500, "audio_max_mo": 8}}
MP3 = bytes.fromhex("fffb90000000000000000000000000000000000000000000")


def api_voix(etat=(200, ETAT_OK), dire=(200, MP3)):
    def f(m, c, corps):
        if c == "/api/v1/voicestudio/usager/etat":
            return etat
        if c == "/api/v1/voicestudio/usager/dire":
            return dire
    return f


def test_voicestudio_420_etat_limites_mesurees_et_dire_poste_la_meme_requete(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "voicestudio", api=api_voix(), taille=T420)
    p.wait_for_function("document.getElementById('etat-t').textContent === 'répond'")
    assert p.inner_text("#tTexte") == "1500" and p.inner_text("#tAudio") == "8" and sans_debordement(p)
    assert p.is_disabled("#b-dire")
    p.fill("#texte", "Bonjour la box")
    assert p.inner_text("#cpt") == "14 / 1500" and not p.is_disabled("#b-dire")
    p.click("#b-dire")
    p.wait_for_function("!document.getElementById('audio').hidden")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/api/v1/voicestudio/usager/dire" and json.loads(post[2]) == {"texte": "Bonjour la box", "format": "mp3"}
    assert p.evaluate("document.getElementById('audio').src.startsWith('blob:')") and err == []
    ctx.close()


def test_voicestudio_mesure_absente_tirets_et_etats_dits(navigateur):
    ctx, p, _, err, _ = ouvre(navigateur, "voicestudio", api=api_voix(etat=(502, {})))
    p.wait_for_function("document.getElementById('etat-t').textContent === 'absent'")
    assert "n'est pas installé sur cette box" in p.inner_text("#note")
    assert p.inner_text("#tTexte") == "—" and p.inner_text("#tAudio") == "—"
    ctx.close()
    ctx, p, _, _, _ = ouvre(navigateur, "voicestudio", api=api_voix(etat=(401, {})))
    p.wait_for_function("document.getElementById('etat-t').textContent === 'connexion'")
    assert "Réservé aux personnes connectées" in p.inner_text("#note")
    ctx.close()
    ctx, p, _, _, _ = ouvre(navigateur, "voicestudio", api=api_voix(dire=(503, {"detail": "Mémoire insuffisante <b>x</b>"})))
    p.wait_for_function("document.getElementById('etat-t').textContent === 'répond'")
    p.fill("#texte", "essai")
    p.click("#b-dire")
    p.wait_for_function("document.getElementById('note').textContent.indexOf('Mémoire insuffisante') >= 0")
    assert "<b>x</b>" in p.inner_text("#note") and p.locator("#note b").count() == 0        # texte, jamais HTML
    ctx.close()


def test_voicestudio_demo_inerte_aucune_ecriture_ni_micro(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "voicestudio", "?demo=1", taille=T420,
                                   init="window.__micro=0;navigator.mediaDevices&&(navigator.mediaDevices.getUserMedia=function(){window.__micro++;return Promise.reject(new Error('non'));});")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#etat-t") == "répond"
    p.fill("#texte", "essai")
    p.click("#b-dire")
    assert "inerte" in p.inner_text("#note")
    p.click("#b-mic")
    assert "inerte" in p.inner_text("#note") and p.evaluate("window.__micro") == 0
    assert appels == [] and err == [] and sans_debordement(p)
    ctx.close()


def test_voicestudio_embed_hauteur_annoncee(navigateur):
    ctx, c, p, err, _ = ouvre(navigateur, "voicestudio", "?embed=1", api=api_voix(), taille={"width": 700, "height": 600}, hote=True)
    c.wait_for_function("document.getElementById('etat-t').textContent === 'répond'")
    assert not c.is_visible("#tuiles") and not c.is_visible(".marque")
    hauteur_annoncee(p, c, "voicestudio")
    assert err == []
    ctx.close()


# ── voicestudio-admin ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def api_admin(statut, corps):
    return lambda m, c, _: (statut, corps) if c == "/api/v1/voicestudio/status" else None


@pytest.mark.parametrize("statut,corps,pastille,note", [
    (200, {"installed": True, "running": True, "operation": {}}, "répond", "Le moteur répond."),
    (200, {"installed": True, "running": False, "asleep": True, "operation": {"etat": "en-cours", "action": "start"}}, "dort", "Le moteur dort"),
    (200, {"installed": True, "running": False, "operation": {}}, "muet", "ne répond pas"),
    (200, {"installed": False, "running": False, "operation": {}}, "à installer", "pas encore installé"),
    (200, {"error": "socket <i>x</i>"}, "injoignable", "Le module ne répond pas : socket <i>x</i>"),
    (502, {}, "absent", "n'est pas installé sur cette box"),
    (401, {}, "réservé", "Réservé aux administrateurs"),
])
def test_voicestudio_admin_les_etats_sont_dits_en_lecture_seule(navigateur, statut, corps, pastille, note):
    ctx, p, _, err, appels = ouvre(navigateur, "voicestudio-admin", api=api_admin(statut, corps), taille=T420)
    p.wait_for_function(f"document.getElementById('etat-t').textContent === {json.dumps(pastille)}")
    assert note in p.inner_text("#note") and p.locator("#note i").count() == 0
    assert sans_debordement(p) and err == []
    assert [a[0] for a in appels] == ["GET"] and appels[0][1] == "/api/v1/voicestudio/status"
    if statut == 200 and "installed" in corps:
        assert p.is_visible("#kpis")
    else:
        assert p.is_hidden("#kpis")
    ctx.close()


def test_voicestudio_admin_demo_et_embed(navigateur):
    ctx, c, p, err, appels = ouvre(navigateur, "voicestudio-admin", "?demo=1&embed=1", taille={"width": 700, "height": 600}, hote=True)
    c.wait_for_function("document.getElementById('etat-t').textContent === 'dort'")
    assert c.is_visible("#demo") and c.is_visible("#kpis") and appels == []
    hauteur_annoncee(p, c, "voicestudio-admin")
    assert err == []
    ctx.close()


# ── zigbee ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

DEVICES = {"pont": "online", "appareils": [
    {"nom": "INTER-BUREAU", "genre": "switch", "etat": "ON", "joignable": True, "qualite": 80},
    {"nom": "LIGHT-SALON", "genre": "light", "etat": "ON", "joignable": True, "luminosite": 127},
    {"nom": "LIGHT-<i>CAVE</i>", "genre": "light", "etat": "OFF", "joignable": False}]}


def api_zigbee(devices=(200, DEVICES), set_=(200, {"ok": True})):
    def f(m, c, _):
        if c == "/api/v1/zigbee/devices":
            return devices
        if c.endswith("/set"):
            return set_
    return f


def test_zigbee_420_liste_mesures_absentes_et_toggle_identique(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "zigbee", api=api_zigbee(), taille=T420)
    p.wait_for_selector("#liste .app2")
    assert p.locator("#liste .app2").count() == 3 and p.inner_text("#n") == "2/3 allumés" and p.inner_text("#pont") == "PONT EN LIGNE"
    assert p.inner_text("#tApps") == "3" and p.inner_text("#tOn") == "2" and p.inner_text("#tInj") == "1"
    lignes = p.locator("#liste .app2")
    assert "50" in lignes.nth(1).locator(".det").inner_text() and lignes.nth(0).locator(".det").inner_text() == ""     # 0 % n'est jamais inventé
    assert "injoignable" in lignes.nth(2).locator(".det").inner_text() and lignes.nth(2).locator("button").is_disabled()
    assert "<i>cave</i>" in lignes.nth(2).locator(".nom").inner_text().lower() and p.locator("#liste i").count() == 0       # texte, jamais HTML
    assert sans_debordement(p) and p.evaluate("[...document.querySelectorAll('.app2')].every(r => r.getBoundingClientRect().right <= innerWidth + 1)")
    lignes.nth(0).locator("button").click()
    p.wait_for_timeout(300)
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/api/v1/zigbee/devices/INTER-BUREAU/set" and json.loads(post[2]) == {"etat": "TOGGLE"}
    assert err == []
    ctx.close()


@pytest.mark.parametrize("code,pastille,texte", [
    (403, "RÉSEAU LOCAL", "réservé au réseau local"),
    (401, "SESSION REQUISE", "Ouvrez votre session"),
    (502, "HORS LIGNE", "injoignable"),
])
def test_zigbee_refus_et_pannes_sont_dits(navigateur, code, pastille, texte):
    ctx, p, _, err, _ = ouvre(navigateur, "zigbee", api=api_zigbee(devices=(code, {})), taille=T420)
    p.wait_for_selector("#msg:not([hidden])")
    assert texte in p.inner_text("#msg") and p.inner_text("#pont") == pastille
    assert [p.inner_text(i) for i in ("#tApps", "#tOn", "#tInj")] == ["—"] * 3 and err == []
    if code == 401:
        assert "session requise" in p.inner_text("#session")
    ctx.close()


def test_zigbee_demo_inerte_aucune_commande_ni_message(navigateur):
    ctx, c, p, err, appels = ouvre(navigateur, "zigbee", "?demo=1", taille=T420, hote=True)
    c.wait_for_selector("#liste .app2")
    assert c.is_visible("#demo") and "DÉMONSTRATION" in c.inner_text("#demo")
    c.locator("#liste .app2 button").first.click()
    assert "inerte" in c.inner_text("#retour")
    c.click("a.pied")
    p.wait_for_timeout(250)
    assert [m for m in p.evaluate("__msgs") if m["d"] and "sbx" in m["d"]] == [] and appels == [] and err == []
    ctx.close()


def test_zigbee_le_pied_ouvre_la_console_par_le_hall(navigateur):
    ctx, c, p, err, _ = ouvre(navigateur, "zigbee", api=api_zigbee(), taille=T420, hote=True)
    c.wait_for_selector("#liste .app2")
    c.click("a.pied")
    p.wait_for_function("__msgs.some(m => m.d && m.d.sbx === 'ouvre')")
    m = [x for x in p.evaluate("__msgs") if x["d"] and x["d"].get("sbx") == "ouvre"][0]["d"]
    assert m["id"] == "zigbee" and m["url"] == "https://zigbee.gk2.secubox.in/"
    assert err == []
    ctx.close()


def test_zigbee_embed_hauteur_annoncee(navigateur):
    ctx, c, p, err, _ = ouvre(navigateur, "zigbee", "?embed=1", api=api_zigbee(), taille={"width": 700, "height": 600}, hote=True)
    c.wait_for_selector("#liste .app2")
    assert not c.is_visible("#tuiles") and not c.is_visible(".marque")
    hauteur_annoncee(p, c, "zigbee")
    assert err == []
    ctx.close()


# ── relais de session ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

RETOUR = "?retour=https%3A%2F%2Fhall.sbx.test%2Fx%3Fa%3D1%23vieux"


def test_relais_renvoie_le_jeton_dans_le_fragment_seulement(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "relais", RETOUR, relais=True, taille=T420,
                                   api=lambda m, c, _: (200, {"jeton": "J T/1"}) if (m, c) == ("POST", "/api/v1/webos/jeton") else None)
    p.wait_for_url("https://hall.sbx.test/**")
    assert p.url == "https://hall.sbx.test/x?a=1#sbx=J%20T%2F1"      # l'ancien fragment est remplacé, le jeton n'est PAS en requête
    assert [a[:2] for a in appels] == [("POST", "/api/v1/webos/jeton")] and err == []
    ctx.close()


def test_relais_destination_hors_liste_close_refusee_sans_demander_de_jeton(navigateur):
    ctx, p, _, err, appels = ouvre(navigateur, "relais", "?retour=https%3A%2F%2Fevil.example%2F", relais=True, taille=T420)
    p.wait_for_function("document.getElementById('msg').textContent.indexOf('non autorisée') >= 0")
    assert p.inner_text("#etat") == "REFUSÉ" and appels == [] and sans_debordement(p) and p.url.startswith("http://sbx.test/relais.html")
    ctx.close()


def test_relais_sans_session_propose_la_connexion_et_sans_html_construit(navigateur):
    ctx, p, _, err, _ = ouvre(navigateur, "relais", RETOUR, relais=True, taille=T420,
                              api=lambda m, c, _: (401, {}) if c == "/api/v1/webos/jeton" else None)
    p.wait_for_selector("#suite a.b2")
    href = p.get_attribute("#suite a.b2", "href")
    assert href.startswith("https://admin.sbx.test/login.html?retour=") and "hall.sbx.test" not in href.split("?retour=")[0]
    assert "Connexion SecuBox" in p.inner_text("#suite") and p.inner_text("#etat") == "SESSION REQUISE"
    assert sans_debordement(p) and err == []
    ctx.close()

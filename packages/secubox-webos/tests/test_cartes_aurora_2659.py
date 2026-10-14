# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2659 — sept cartes du Hall au profil Aurora (freeboxtv, ipv6guard, lyrion, metablog, peertube, quick, quifrappe).

Statique pour chaque carte, puis vrai navigateur (Chromium, API simulée sur http://sbx.test, données factices) :
mêmes appels d'API qu'avant, mesure absente « — », bandeau sans session, démonstration sans écriture, 420 px sans débordement,
hauteur annoncée à l'hôte, mêmes messages vers le Hall."""
import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

HALL = Path(__file__).resolve().parents[1] / "www" / "hall"
CARTES = HALL / "cardlets"
NOMS = ["freeboxtv", "ipv6guard", "lyrion", "metablog", "peertube", "quick", "quifrappe"]
SRC = {n: (CARTES / f"{n}.html").read_text(encoding="utf-8") for n in NOMS}
# Scripts de même origine que chaque carte a le droit de charger (contrat des cartes du Hall : garde des sondes, domaine, aide).
SCRIPTS = {
    "freeboxtv": ["../sonde.js", "/hls.min.js"],
    "ipv6guard": ["../sonde.js"],
    "lyrion": ["../sonde.js", "../aide.js"],
    "metablog": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js"],
    "peertube": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
    "quick": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
    "quifrappe": ["/api/v1/webos/public/hotes.js", "../domaine.js", "../sonde.js", "../aide.js"],
}
ONGLET = {"freeboxtv": "freeboxtv", "ipv6guard": "ipv6guard", "lyrion": "lyrion", "metablog": "metablog",
          "peertube": "peertube", "quick": "quick-", "quifrappe": "quifrappe"}


# ───────────────────────── statique : chaque carte ─────────────────────────

@pytest.mark.parametrize("nom", NOMS)
def test_page_aurora_autonome_sans_dialogue_natif(nom):
    t = SRC[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in t and "Copyright (c) 2026 CyberMind" in t
    assert re.findall(r'<script src="([^"]+)"', t) == SCRIPTS[nom]            # aucune dépendance distante
    assert "--fond:#060d1b" in t and "container-type:inline-size" in t and "container-name:a" in t
    assert "data-theme" not in t and "prefers-color-scheme" not in t            # thème unique sombre
    assert "hybrid-skin" not in t and "spicy.css" not in t and "SBXSliceBar" not in t and "slicebar.js" not in t and "slicebar.css" not in t
    assert not re.search(r"<[^>]*\sonclick=", t)                                  # pas de gestionnaire en attribut
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(",
                     "new Function", "http://", "cdn."):
        assert interdit not in t, f"{nom} : {interdit}"
    assert "lorem" not in t.lower()
    assert "[hidden]{display:none!important}" in t.replace(" ", "")
    assert "min-height:100vh" not in t and "documentElement.scrollHeight" not in t


@pytest.mark.parametrize("nom", NOMS)
def test_hauteur_annoncee_par_le_cadre_et_demo_embed(nom):
    t = SRC[nom]
    assert "sbxVue" in t and "querySelector('.cadre').getBoundingClientRect().bottom" in t.replace('"', "'")
    assert re.search(r"onglet:\s*['\"]" + ONGLET[nom], t) and "location.origin" in t and "ResizeObserver" in t
    assert re.search(r"get\(['\"]demo['\"]\)", t) and re.search(r"get\(['\"]embed['\"]\)", t)
    assert "—" in t                                                            # mesure absente = « — »
    assert "Aucune mesure : session requise" in t or nom in ("quifrappe", "metablog", "peertube")


@pytest.mark.parametrize("nom", ["freeboxtv", "ipv6guard", "metablog", "peertube", "quifrappe"])
def test_cartes_en_lecture_seule_n_ecrivent_rien(nom):
    t = SRC[nom]
    assert not re.search(r"\b(POST|PUT|DELETE|PATCH)\b", t) and "XMLHttpRequest" not in t
    assert not re.search(r"method:\s*['\"]", t)                                      # aucun fetch avec une méthode : que des GET


def test_la_demonstration_n_ecrit_rien_lyrion_et_quick():
    ly, qk = SRC["lyrion"], SRC["quick"]
    assert re.search(r"function post\(p, body\) \{\s*if \(DEMO\)", ly)
    assert "function casteBroadcast(id) {\n    if (DEMO)" in ly and "if (DEMO || parent === window) return;" in ly   # ni requête ni message média
    assert re.search(r"function api\(chemin, opts\) \{\s*opts = opts \|\| \{\};\s*// [^\n]*\n\s*if \(DEMO\)", qk)
    assert re.search(r"function envoie\(\) \{\s*var d = el\('depose'\);\s*if \(!enAttente \|\| d\.classList\.contains\('envoi'\)\) return;\s*if \(DEMO\)", qk)


# ───────────────────────── statique : mêmes appels, mêmes messages ─────────────────────────

def test_freeboxtv_meme_mecanisme_de_lecture():
    t = SRC["freeboxtv"]
    assert "var API='/api/v1/freeboxtv'" in t and "fetch(API+'/channels'" in t
    for m in ("new Hls({enableWorker:false, maxBufferLength:12, liveSyncDurationCount:3", "manifestLoadingTimeOut:25000", "fragLoadingMaxRetry:6",
              "hls.loadSource(url); hls.attachMedia(v);", "hls.on(Hls.Events.MANIFEST_PARSED, lance);", "hls.startLoad()", "hls.recoverMediaError()",
              "v.muted=true; v.autoplay=true;", "application/vnd.apple.mpegurl", "NotAllowedError", "addEventListener('pagehide', stop)",
              "pointer-events:none"):
        assert m in t, m


def test_ipv6guard_meme_appel_et_langage_courant():
    t = SRC["ipv6guard"]
    assert "var API = '/api/v1/ipv6guard/';" in t and "fetch(API + 'status'" in t
    for mot in ("Appareils joignables en IPv6", "Voir les appareils", "Lecture seule", "adresse publique", "Connexion requise", "Indisponible"):
        assert mot in t
    for jargon in ("SLAAC", "NDP", "conntrack", "nft"):
        assert jargon not in t


def test_lyrion_memes_routes_et_messages():
    t = SRC["lyrion"]
    assert "var API = '/api/v1/lyrion';" in t
    for r in ("getj('/players')", "getj('/now-playing')", "'/player/' + encodeURIComponent(id) + '/power'", "{ on:on }",
              "'/action/' + (jouePP ? 'pause' : 'play')", "'/volume', { level: Number(this.value) }", "'/play-url', { url:url }",
              "/api/v1/webos/public/broadcast", "method:'POST'"):
        assert r in t, r
    assert "sbx:'media', id:'lyrion', type:'audio'" in t and "sbx:'ouvre', id:'lyrion'" in t
    assert "d.sbx === 'cmd'" in t and "d.sbx === 'cast'" in t and "estWebClient" in t


def test_metablog_memes_lectures_et_tris():
    t = SRC["metablog"]
    assert '"/api/v1/metablogizer/public/mosaique"' in t and '"/api/v1/metablogizer/site/"' in t and '"/screenshot"' in t
    assert 'window.open("https://" + s.domain + "/", "_blank", "noopener")' in t and "&edit=1" in t
    for tri in ("Récents", "Illustrés", "A–Z", "Sans aperçu"):
        assert tri in t
    assert '"mega"' in t and "data-mega" in t


def test_peertube_memes_lectures_et_lecteur_amont():
    t = SRC["peertube"]
    for r in ("/pt/api/v1/videos?count=24&sort=-publishedAt&nsfw=false", "/pt/api/v1/videos?count=24&sort=-views&nsfw=false", "/pt/api/v1/video-channels?count=18&sort=-createdAt",
              "/pt/api/v1/video-playlists?count=18&sort=-updatedAt", "/pt/api/v1/videos/categories", "categoryOneOf=", "/api/v1/profiles/lifecycles",
              "/videos/embed/", "?api=1&autoplay=1&title=0&warningTitle=0&peertubeLink=0", "'publish-reply'", "publish: []", "slice(-7) === '__ready'",
              "sbx.peertube.etat"):
        assert r in t, r
    assert "sbx: 'media', id: 'peertube'" in t and "sbx: 'ouvre', id: 'peertube'" in t and "d.action === 'zoom'" in t


def test_quick_memes_appels_et_gabarit_cloud_intact():
    t = SRC["quick"]
    for r in ("'/adm/api/v1/' + c.mod + '/status'", "'/api/v1/webos' + chemin", "'/public/actions/' + ACTIONNABLE[id] + '/liste'",
              "'/actions/' + ACTIONNABLE[id] + '/ajouter'", "'/actions/' + ACTIONNABLE[id] + '/' + b.dataset.a", "'/depot/reglages'",
              "x.open('POST', '/api/v1/webos/depot')", "fd.append('fichiers'", "fd.append('mot'", "'/public/actions/droplet/stockage'",
              "{ name: it.dataset.id } : { id: it.dataset.id }", "sbx: 'voir'", "sbx: 'ouvre', id: id", "/sbx/entrer"):
        assert r in t, r


def test_quifrappe_meme_lecture_publique_et_message():
    t = SRC["quifrappe"]
    assert "fetch('/api/v1/webos/public/waf/qui-frappe'" in t and "sbx: 'ouvre', id: 'quifrappe'" in t and "https://waf.gk2.secubox.in/" in t


# ───────────────────────── vrai navigateur ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


ENREGISTRE = """window.__msgs = []; addEventListener('message', function(e){ try { window.__msgs.push(JSON.parse(JSON.stringify(e.data))); } catch (x) {} });"""


def ouvre(navigateur, nom, qs, routes, taille=None, init=None):
    """Ouvre la carte `nom` sur http://sbx.test ; `routes` : chemin d'API → (statut, corps) ; renvoie (ctx, page, erreurs, appels)."""
    ctx = navigateur.new_context(viewport=taille or {"width": 1100, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.add_init_script(ENREGISTRE)
    if init:
        p.add_init_script(init)

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("cardlets/"):
            r.fulfill(status=200, content_type="text/html", body=(CARTES / chemin.split("/", 1)[1]).read_text(encoding="utf-8"))
        elif chemin in ("domaine.js", "sonde.js", "aide.js"):
            r.fulfill(status=200, content_type="application/javascript", body=(HALL / chemin).read_text(encoding="utf-8"))
        elif chemin.endswith("hotes.js") or chemin == "hls.min.js":
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin.startswith("api/") or chemin.startswith("adm/api/") or chemin.startswith("pt/api/"):
            chemin = unquote(chemin)
            appels.append((r.request.method, "/" + chemin, r.request.post_data))
            val = routes.get("/" + chemin)
            if val is None:
                r.fulfill(status=404, content_type="application/json", body="{}")
            else:
                statut, corps = val(r) if callable(val) else val
                r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto(f"http://sbx.test/cardlets/{nom}.html{qs}")
    return ctx, p, erreurs, appels


def pas_de_debordement(p):
    return p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def hauteurs(p):
    return [m["sbxVue"] for m in p.evaluate("window.__msgs") if isinstance(m, dict) and "sbxVue" in m]


def attend_appel(p, appels, methode, chemin, delai=5000):
    """Attend qu'un appel (méthode, chemin) ait été vu par la simulation d'API."""
    t = 0
    while t < delai and not [a for a in appels if a[0] == methode and a[1] == chemin]:
        p.wait_for_timeout(50)
        t += 50
    assert [a for a in appels if a[0] == methode and a[1] == chemin], (methode, chemin)


def textes(p, sels):
    return [p.inner_text(s) for s in sels]


# ----- freeboxtv -----

CHAINES = {"channels": [{"id": "c1", "lcn": 1, "name": "Cinéma Libre", "hls": "/api/v1/freeboxtv/hls/c1/index.m3u8"},
                        {"id": "c2", "lcn": 2, "name": "Atelier TV", "hls": "/api/v1/freeboxtv/hls/c2/index.m3u8"},
                        {"id": "c3", "lcn": 27, "name": "Nature Démo", "hls": "/api/v1/freeboxtv/hls/c3/index.m3u8"}]}


def test_freeboxtv_chaines_filtre_et_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "freeboxtv", "", {"/api/v1/freeboxtv/channels": (200, CHAINES)}, {"width": 420, "height": 800})
    p.wait_for_selector("#grille .ch")
    assert textes(p, ["#tNb", "#tAff", "#tLecture"]) == ["3", "3", "—"] and p.inner_text("#etat") == "PRÊT"
    assert p.locator("#grille .ch").count() == 3 and "Cinéma Libre" in p.inner_text("#grille")
    p.fill("#q", "nature")
    assert p.inner_text("#tAff") == "1" and p.locator("#grille .ch").count() == 1
    p.fill("#q", "27")                       # le numéro de chaîne filtre aussi
    assert p.locator("#grille .ch").count() == 1
    p.fill("#q", "zzz")
    assert "Aucune chaîne." in p.inner_text("#grille") and p.inner_text("#tAff") == "0"
    assert pas_de_debordement(p) and err == [] and hauteurs(p) and all(h > 300 for h in hauteurs(p))
    assert [a for a in appels if a[0] != "GET"] == [] and appels[0][1] == "/api/v1/freeboxtv/channels"
    ctx.close()


def test_freeboxtv_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "freeboxtv", "", {"/api/v1/freeboxtv/channels": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert textes(p, ["#tNb", "#tAff", "#tLecture"]) == ["—", "—", "—"] and err == []
    ctx.close()


def test_freeboxtv_hors_ligne_dit_hors_ligne_avec_reessai(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "freeboxtv", "", {"/api/v1/freeboxtv/channels": (502, {})})
    p.wait_for_selector("#msg:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and "injoignable" in p.inner_text("#msg") and p.locator("#msg .btn").count() == 1 and err == []
    ctx.close()


def test_freeboxtv_demo_annoncee_lecture_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "freeboxtv", "?demo=1", {})
    p.wait_for_selector("#grille .ch")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.locator("#grille .ch").count() == 12
    p.click("#grille .ch >> nth=2")
    p.wait_for_selector("#retour:not([hidden])")
    assert "inerte" in p.inner_text("#retour") and not p.is_visible("#screen")
    assert appels == [] and err == []
    ctx.close()


def test_freeboxtv_lecture_reelle_monte_la_source_hls(navigateur):
    # sans hls.js (stub vide), Chromium lit-il le HLS nativement ? On vérifie seulement que la carte tente une source ou le dit.
    ctx, p, err, appels = ouvre(navigateur, "freeboxtv", "", {"/api/v1/freeboxtv/channels": (200, CHAINES)})
    p.wait_for_selector("#grille .ch")
    p.click("#grille .ch >> nth=0")
    assert p.is_visible("#screen") and p.locator("#grille .ch.on").count() == 1 and p.inner_text("#tLecture") == "Cinéma Libre"
    p.wait_for_function("document.getElementById('v').getAttribute('src') || /indisponible/.test(document.getElementById('spin').textContent)")
    assert err == []
    ctx.close()


# ----- ipv6guard -----

STATUT_V6 = {"verdict": {"niveau": "a_verifier", "titre": "À vérifier", "explication": "Pare-feu non lu.", "sensibles": 2},
             "etapes": [{"id": "appareils", "titre": "Appareils joignables en IPv6", "valeur": 2, "detail": "vus", "etat": "ok"},
                        {"id": "services", "titre": "Services visibles", "valeur": 0, "detail": "aucun", "etat": "ok"},
                        {"id": "bloquees", "titre": "Connexions entrantes bloquées", "valeur": None, "detail": "non lu", "etat": "non_lu"},
                        {"id": "exceptions", "titre": "Exceptions autorisées", "valeur": None, "detail": "non lu", "etat": "non_lu"}],
             "appareils": [{"nom": "Serveur <b>x</b>", "modele": "Boîtier", "adresses_publiques": ["2001:db8::1"], "routeur": False,
                            "services": [{"libelle": "SSH", "sensible": True}]}],
             "mesure": {"date": 1760000000, "mdns_en_cours": False}}


def test_ipv6guard_verdict_etapes_et_appareils_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "ipv6guard", "", {"/api/v1/ipv6guard/status": (200, STATUT_V6)}, {"width": 420, "height": 800})
    p.wait_for_selector("#chaine .tuile")
    assert p.inner_text("#titre") == "À vérifier" and p.inner_text("#etat") == "À VÉRIFIER" and p.get_attribute("#verdict", "data-niveau") == "a_verifier"
    assert "2 services sensibles" in p.inner_text("#expl")
    vals = p.eval_on_selector_all("#chaine .tuile .v", "els => els.map(e => e.textContent)")
    assert vals == ["2", "0", "—", "—"]                      # 0 est une mesure, l'absence est « — »
    assert p.locator("#chaine .tuile.nul").count() == 2 and p.get_attribute("#chaine .tuile >> nth=0", "title")
    assert not p.is_visible("#liste")
    p.click("#plus")
    assert p.is_visible("#liste") and "adresse publique" in p.inner_text("#liste") and p.get_attribute("#plus", "aria-expanded") == "true"
    assert "<b>x</b>" in p.inner_text("#liste") and p.locator("#liste b b").count() == 0     # le HTML venu du serveur reste du texte
    assert pas_de_debordement(p) and err == [] and hauteurs(p) and [a[0] for a in appels] == ["GET"]
    ctx.close()


def test_ipv6guard_sans_session_et_indisponible(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "ipv6guard", "", {"/api/v1/ipv6guard/status": (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#titre") == "Connexion requise" and p.inner_text("#etat") == "SESSION REQUISE" and err == []
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "ipv6guard", "", {"/api/v1/ipv6guard/status": (500, {})})
    p.wait_for_function("document.getElementById('titre').textContent === 'Indisponible'")
    assert p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


def test_ipv6guard_demo_annoncee_sans_requete(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "ipv6guard", "?demo=1", {})
    p.wait_for_selector("#chaine .tuile")
    assert p.is_visible("#demo") and p.locator("#chaine .tuile").count() == 4 and appels == [] and err == []
    ctx.close()


# ----- lyrion -----

PLAYERS = {"players": [{"id": "00:00:5e:00:53:01", "name": "Salon", "model": "Boom", "power": True},
                       {"id": "02:42:53:42:57:01", "name": "Mozilla de x", "model": "Web Client", "power": True}]}
NOW = {"mode": "play", "title": "Titre <i>x</i>", "artist": "Artiste", "album": "Album", "player": "Salon"}


def routes_lyrion(**plus):
    r = {"/api/v1/lyrion/players": (200, PLAYERS), "/api/v1/lyrion/now-playing": (200, NOW), "/api/v1/webos/public/broadcast": (200, {"actif": False}),
         "/api/v1/lyrion/player/00:00:5e:00:53:01/action/pause": (200, {"ok": True}), "/api/v1/lyrion/player/00:00:5e:00:53:01/volume": (200, {"ok": True}),
         "/api/v1/lyrion/player/00:00:5e:00:53:01/power": (200, {"ok": True}), "/api/v1/lyrion/player/00:00:5e:00:53:01/action/next": (200, {"ok": True})}
    r.update(plus)
    return r


def test_lyrion_etat_commandes_memes_appels_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "lyrion", "", routes_lyrion(), {"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tt').textContent !== '—'")
    assert p.inner_text("#tt") == "Titre <i>x</i>" and p.locator(".np i").count() == 0
    assert textes(p, ["#rang", "#tLecteur", "#tMode", "#etat"]) == ["1", "Salon", "lecture", "EN LECTURE"]     # le client web fantôme est écarté
    assert pas_de_debordement(p) and hauteurs(p)
    p.click("#pp")                                        # lecture en cours : bascule en pause
    p.wait_for_timeout(200)
    p.click("[data-a=next]")
    p.evaluate("(() => { const v = document.getElementById('vol'); v.value = 30; v.dispatchEvent(new Event('change')); })()")
    p.click("#pw")
    p.wait_for_timeout(500)
    posts = [(m, c, b) for (m, c, b) in appels if m == "POST"]
    assert ("POST", "/api/v1/lyrion/player/00:00:5e:00:53:01/action/pause", None) in posts
    assert ("POST", "/api/v1/lyrion/player/00:00:5e:00:53:01/action/next", None) in posts
    assert ("POST", "/api/v1/lyrion/player/00:00:5e:00:53:01/volume", '{"level":30}') in posts
    assert ("POST", "/api/v1/lyrion/player/00:00:5e:00:53:01/power", '{"on":false}') in posts
    assert err == []
    ctx.close()


def test_lyrion_sans_session_dit_session_requise_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "lyrion", "", {"/api/v1/lyrion/players": (401, {}), "/api/v1/lyrion/now-playing": (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and textes(p, ["#rang", "#tLecteur", "#tMode"]) == ["—", "—", "—"] and err == []
    ctx.close()


def test_lyrion_demo_inerte_sans_requete_ni_message_media(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "lyrion", "?demo=1", {})
    p.wait_for_function("document.getElementById('tt').textContent === 'Morceau fictif'")
    assert p.is_visible("#demo")
    p.click("#pp")
    p.wait_for_selector("#toast:not([hidden])")
    assert "inerte" in p.inner_text("#toast")
    p.click("#pw")
    p.click("[data-a=cast]")
    assert appels == [] and err == []
    ctx.close()


def test_lyrion_dans_le_hall_annonce_media_et_hauteur(navigateur):
    ctx = navigateur.new_context(viewport={"width": 420, "height": 800})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    corps = {"/api/v1/lyrion/players": PLAYERS, "/api/v1/lyrion/now-playing": NOW, "/api/v1/webos/public/broadcast": {"actif": False}}

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "hote.html":
            r.fulfill(status=200, content_type="text/html", body="<iframe id=f src='/cardlets/lyrion.html' style='width:420px;height:300px'></iframe><script>window.m=[];addEventListener('message',e=>m.push(e.data))</script>")
        elif chemin == "cardlets/lyrion.html":
            r.fulfill(status=200, content_type="text/html", body=(CARTES / "lyrion.html").read_text(encoding="utf-8"))
        elif chemin in ("sonde.js", "domaine.js", "aide.js"):
            r.fulfill(status=200, content_type="application/javascript", body=(HALL / chemin).read_text(encoding="utf-8"))
        elif "/" + chemin in corps:
            r.fulfill(status=200, content_type="application/json", body=json.dumps(corps["/" + chemin]))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/hote.html")
    p.wait_for_function("window.m.some(x => x && x.sbx === 'media')")
    msgs = p.evaluate("window.m")
    media = [x for x in msgs if x.get("sbx") == "media"][0]
    assert media["id"] == "lyrion" and media["type"] == "audio" and media["joue"] is True and media["titre"] == "Titre <i>x</i>"
    vue = [x for x in msgs if "sbxVue" in x]
    assert vue and vue[-1]["onglet"] == "lyrion" and vue[-1]["sbxVue"] > 300
    assert p.frames[1].evaluate("document.body.classList.contains('dans')")
    f = p.frames[1]
    f.click("#pied")
    p.wait_for_function("window.m.some(x => x && x.sbx === 'ouvre')")
    assert [x for x in p.evaluate("window.m") if x.get("sbx") == "ouvre"][0]["id"] == "lyrion"
    assert erreurs == []
    ctx.close()


# ----- metablog -----

MOSAIQUE = {"sites": [{"name": "atelier", "title": "Atelier du Lac", "domain": "atelier.example", "last_updated": "2026-10-12", "vignette": True},
                      {"name": "carnet", "title": "Carnet", "domain": "carnet.example", "last_updated": "2026-10-10", "vignette": False},
                      {"name": "radio", "title": "Radio", "domain": "radio.example", "last_updated": "2026-10-14", "vignette": True}]}


def test_metablog_sites_tris_et_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "metablog", "", {"/api/v1/metablogizer/public/mosaique": (200, MOSAIQUE)}, {"width": 420, "height": 800})
    p.wait_for_selector("#hero:not([hidden])")
    assert textes(p, ["#tSites", "#tAvec", "#tSans", "#tTri"]) == ["3", "2", "1", "🆕 Récents"] and p.inner_text("#etat") == "CAPTURES EN COURS"
    assert p.inner_text("#une-t") == "Radio" and p.inner_text("#une-d") == "radio.example"          # le plus récent
    assert p.locator("#bande .vig").count() == 2
    p.click("#onglets >> text=A–Z")
    assert p.inner_text("#une-t") == "Atelier du Lac" and p.get_attribute("#onglets button >> nth=2", "aria-selected") == "true"
    p.click("#onglets >> text=Sans aperçu")
    assert p.inner_text("#une-t") == "Carnet" and not p.is_visible("#une-img") and p.is_visible("#une-sans")
    assert pas_de_debordement(p) and err == [] and hauteurs(p)
    assert any(a[1] == "/api/v1/metablogizer/site/atelier/screenshot" for a in appels) and all(a[0] == "GET" for a in appels)
    ctx.close()


def test_metablog_clic_ouvre_le_site_et_le_reglage_demande_une_session(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "metablog", "", {"/api/v1/metablogizer/public/mosaique": (200, MOSAIQUE)})
    ctx.route("https://radio.example/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body="ok"))
    p.wait_for_selector("#hero:not([hidden])")
    assert not p.is_visible("#une-reg")                                  # invité : pas de réglage
    with p.expect_popup() as pop:
        p.click("#une")
    assert pop.value.url == "https://radio.example/"
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "metablog", "", {"/api/v1/metablogizer/public/mosaique": (200, MOSAIQUE)}, init="localStorage.setItem('sbx_token','x')")
    p.wait_for_selector("#hero:not([hidden])")
    assert p.is_visible("#une-reg") and err == []
    ctx.close()


def test_metablog_panne_vide_et_demo(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "metablog", "", {"/api/v1/metablogizer/public/mosaique": (200, {"sites": []})})
    p.wait_for_function("document.getElementById('etat').textContent === 'AUCUN SITE'")
    assert textes(p, ["#tSites", "#tAvec", "#tSans"]) == ["—", "—", "—"] and p.is_hidden("#hero") and err == []
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "metablog", "", {})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert "injoignable" in p.inner_text("#etatmsg") and err == []
    ctx.close()
    ctx, p, err, appels = ouvre(navigateur, "metablog", "?demo=1", {})
    p.wait_for_selector("#hero:not([hidden])")
    assert p.is_visible("#demo") and p.inner_text("#tSites") == "6"
    p.click("#une")
    assert "inerte" in p.inner_text("#retour") and appels == [] and err == []
    ctx.close()


# ----- peertube -----

VIDEOS = {"total": 31, "data": [{"uuid": f"u{i}", "name": f"Vidéo {i} <b>", "duration": 125 + i, "views": 10 * i, "thumbnailPath": f"/lazy-static/thumbnails/u{i}.jpg",
                                 "channel": {"displayName": "Chaîne <i>A</i>"}} for i in range(1, 10)]}
LIFE = {"lifecycles": [{"id": "peertube", "lifecycle": "always", "sleep_state": "up"}]}


def routes_pt(**plus):
    r = {"/pt/api/v1/videos": (200, VIDEOS), "/api/v1/profiles/lifecycles": (200, LIFE)}
    r.update(plus)
    return r


def test_peertube_catalogue_vues_et_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "peertube", "", routes_pt(), {"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tNb').textContent === '31'")
    assert p.inner_text("#une-t") == "Vidéo 1 <b>" and p.locator("#une b").count() == 0 and p.inner_text("#une-dur") == "2:06"
    assert p.inner_text("#etat") == "PRÊT" and p.locator("#top button").count() == 8 and p.inner_text("#pied-t") == "Chaîne <i>A</i>"
    assert p.inner_text("#tService") == "permanent" and p.inner_text("#tLecture") == "—"
    assert "9 affichées" in p.inner_text("#tNbS")
    assert pas_de_debordement(p) and err == [] and hauteurs(p)
    p.click("#onglets >> text=Populaires")
    p.wait_for_function("document.getElementById('tVue').textContent.includes('Populaires')")
    assert any("sort=-views" in a[1] or a[1] == "/pt/api/v1/videos" for a in appels) and all(a[0] == "GET" for a in appels)
    ctx.close()


def test_peertube_lecture_cadre_poignee_de_main_et_retour_vitrine(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "peertube", "", routes_pt())
    ctx.route("https://peertube.gk2.secubox.in/**", lambda r, *_: r.fulfill(status=200, content_type="text/html",
              body="<script>addEventListener('message',e=>parent.postMessage({echo:e.data},'*'))</script>"))
    p.evaluate("window.__echo=[]; addEventListener('message',e=>{ if(e.data && e.data.echo !== undefined) window.__echo.push(e.data.echo); })")
    p.wait_for_selector("#lire")
    p.click("#lire")
    p.wait_for_selector("#cadre-pt")
    src = p.get_attribute("#cadre-pt", "src")
    assert src.startswith("https://peertube.gk2.secubox.in/videos/embed/u1?api=1&autoplay=1&title=0&warningTitle=0&peertubeLink=0")
    assert p.inner_text("#etat") == "EN LECTURE" and p.inner_text("#tLecture") == "Vidéo 1 <b>" and p.is_visible("#zoom")
    # le lecteur salue (jschannel) : la réponse est un objet publish-reply avec une liste vide, jamais une chaîne
    p.evaluate("""(() => { const c = document.getElementById('cadre-pt');
        window.dispatchEvent(new MessageEvent('message', { source: c.contentWindow, data: JSON.stringify({ id: 7, method: 'peertube::__ready', params: { type: 'publish-request' } }) })); })()""")
    p.wait_for_function("window.__echo.length > 0")
    rep = json.loads(p.evaluate("window.__echo[0]"))
    assert rep == {"id": 7, "method": "peertube::__ready", "params": {"type": "publish-reply", "publish": []}}
    # un ordre « stop » du Hall rend la carte à sa vitrine
    p.evaluate("window.dispatchEvent(new MessageEvent('message', { data: { sbx: 'cmd', action: 'stop' } }))")
    p.wait_for_selector("#lire")
    assert p.locator("#cadre-pt").count() == 0 and p.inner_text("#tLecture") == "—" and err == []
    ctx.close()


def test_peertube_dans_le_hall_annonce_media_ouvre_et_hauteur(navigateur):
    ctx = navigateur.new_context(viewport={"width": 420, "height": 800})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    api = {"/pt/api/v1/videos": VIDEOS, "/api/v1/profiles/lifecycles": LIFE}

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "hote.html":
            r.fulfill(status=200, content_type="text/html", body="<iframe src='/cardlets/peertube.html' style='width:420px;height:300px'></iframe><script>window.m=[];addEventListener('message',e=>m.push(e.data))</script>")
        elif chemin == "cardlets/peertube.html":
            r.fulfill(status=200, content_type="text/html", body=(CARTES / "peertube.html").read_text(encoding="utf-8"))
        elif chemin in ("sonde.js", "domaine.js", "aide.js"):
            r.fulfill(status=200, content_type="application/javascript", body=(HALL / chemin).read_text(encoding="utf-8"))
        elif chemin.endswith("hotes.js"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif "/" + chemin in api:
            r.fulfill(status=200, content_type="application/json", body=json.dumps(api["/" + chemin]))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    ctx.route("https://peertube.gk2.secubox.in/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body="<p>lecteur</p>"))
    p.goto("http://sbx.test/hote.html")
    f = p.frames[1]
    f.wait_for_selector("#lire")
    assert f.evaluate("document.body.classList.contains('dans')")
    f.click("#lire")
    p.wait_for_function("window.m.some(x => x && x.sbx === 'media' && x.joue === true)")
    media = [x for x in p.evaluate("window.m") if x.get("sbx") == "media" and x.get("joue")][0]
    assert media["id"] == "peertube" and media["type"] == "video" and media["href"] == "https://peertube.gk2.secubox.in/w/u1" and media["titre"] == "Vidéo 1 <b>"
    f.click("#pied")
    p.wait_for_function("window.m.some(x => x && x.sbx === 'ouvre')")
    vue = [x for x in p.evaluate("window.m") if "sbxVue" in x]
    assert vue and vue[-1]["onglet"] == "peertube" and erreurs == []
    ctx.close()


def test_peertube_sans_reponse_dit_hors_ligne_et_demo_inerte(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "peertube", "", {"/api/v1/profiles/lifecycles": (200, LIFE)})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert p.inner_text("#tNb") == "—" and err == []
    ctx.close()
    ctx, p, err, appels = ouvre(navigateur, "peertube", "?demo=1", {})
    p.wait_for_function("document.getElementById('tNb').textContent === '9'")
    assert p.is_visible("#demo") and p.locator("#top button").count() == 8
    p.click("#lire")
    assert "inerte" in p.inner_text("#retour") and p.locator("#cadre-pt").count() == 0
    p.click("#onglets >> text=Chaînes")
    p.wait_for_function("document.getElementById('une-dur').textContent === '📺 chaîne'")
    assert appels == [] and err == []
    ctx.close()


def test_peertube_service_en_veille_ne_reveille_pas(navigateur):
    dort = {"lifecycles": [{"id": "peertube", "lifecycle": "on-demand", "sleep_state": "asleep"}]}
    ctx, p, err, appels = ouvre(navigateur, "peertube", "", {"/api/v1/profiles/lifecycles": (200, dort)})
    p.wait_for_function("document.getElementById('tService').textContent === 'en veille'")
    p.wait_for_timeout(300)
    assert p.is_visible("#veille") and "en veille" in p.inner_text("#une-t")
    assert not [a for a in appels if a[1].startswith("/pt/")] and err == []      # aucune sonde de fond : pas de réveil
    ctx.close()


# ----- quick -----

STATUT_DEPOT = {"sites_count": 3, "apps_count": 0, "disk_free": 5 * 1024 ** 3}
LISTE_DEPOT = {"ok": True, "donnees": {"droplets": [{"name": "site-a", "enabled": True, "domain": "a.example", "type": "static"},
                                                    {"name": "appli-b <b>", "enabled": False, "domain": "", "type": "streamlit"}]}}


def routes_depot(**plus):
    r = {"/adm/api/v1/droplet/status": (200, STATUT_DEPOT), "/api/v1/webos/public/actions/droplet/liste": (200, LISTE_DEPOT),
         "/api/v1/webos/public/actions/droplet/stockage": (200, {"donnees": {"total_human": "1,2 Go", "file_count": 4, "max_upload_mb": 256}}),
         "/api/v1/webos/depot/reglages": (200, {"donnees": {"actif": True, "fichiers_max": 5, "taille_max": 100 * 1024 * 1024}}),
         "/api/v1/webos/actions/droplet/supprimer": (200, {"ok": True})}
    r.update(plus)
    return r


def test_quick_depot_tuiles_liste_et_mesure_absente(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "quick", "?svc=depot", routes_depot(), {"width": 420, "height": 800})
    p.wait_for_selector("#items .it")
    assert p.inner_text("#nom") == "Dépôt" and p.inner_text("#etat") == "À JOUR"
    vals = p.eval_on_selector_all("#tuiles .tuile .v", "els => els.map(e => e.textContent)")
    assert vals == ["3", "0"]                                  # 0 est une mesure
    assert "5.0 Go libres" in p.inner_text("#note") and "1,2 Go déposés" in p.inner_text("#piedStock")
    assert p.locator("#items .it a.nm").get_attribute("href") == "https://a.example/" and "appli-b <b>" in p.inner_text("#items") and p.locator("#items b").count() == 0
    p.wait_for_selector("#lim:not(:empty)")
    assert "5 fichiers" in p.inner_text("#lim")
    assert pas_de_debordement(p) and err == [] and hauteurs(p) and hauteurs(p)[-1] > 250
    ctx.close()
    # un chiffre que le service ne donne pas est « — », jamais 0
    ctx, p, err, _ = ouvre(navigateur, "quick", "?svc=depot", routes_depot(**{"/adm/api/v1/droplet/status": (200, {"sites_count": 3})}))
    p.wait_for_selector("#tuiles .tuile")
    assert p.eval_on_selector_all("#tuiles .tuile .v", "els => els.map(e => e.textContent)") == ["3", "—"] and err == []
    ctx.close()


def test_retrait_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "quick", "?svc=depot", routes_depot())
    p.wait_for_selector("#items .it button")
    p.locator("#items .it").first.get_by_text("✕").click()
    assert p.locator("#items .it").first.get_by_text("Confirmer").count() == 1 and p.locator("#items .it").first.get_by_text("Annuler").count() == 1
    assert not [a for a in appels if a[0] == "POST"]               # pas encore : il faut confirmer
    p.locator("#items .it").first.get_by_text("Annuler").click()
    assert p.locator("#items .it").first.get_by_text("✕").count() == 1 and not [a for a in appels if a[0] == "POST"]
    p.locator("#items .it").first.get_by_text("✕").click()
    p.locator("#items .it").first.get_by_text("Confirmer").click()
    attend_appel(p, appels, "POST", "/api/v1/webos/actions/droplet/supprimer")
    assert ("POST", "/api/v1/webos/actions/droplet/supprimer", '{"name":"site-a"}') in appels
    ctx.close()


def test_torrent_ajout_envoie_le_meme_corps(navigateur):
    routes = {"/adm/api/v1/torrent/status": (200, {"total": 2, "downloading": 1, "to_peertube": 0}),
              "/api/v1/webos/public/actions/torrent/liste": (200, {"ok": True, "donnees": [{"name": "iso", "complete": 0, "infohash": "h1"}]}),
              "/api/v1/webos/actions/torrent/ajouter": (200, {"ok": True}), "/api/v1/webos/actions/torrent/pause": (200, {"ok": True})}
    ctx, p, err, appels = ouvre(navigateur, "quick", "?svc=torrent", routes)
    p.wait_for_selector("#mag")
    assert p.eval_on_selector_all("#tuiles .tuile .v", "els => els.map(e => e.textContent)") == ["2", "1", "0"] and p.locator("#tuiles .tuile.att").count() == 1
    p.fill("#mag", "magnet:?xt=urn:btih:abc")
    p.click("#go")
    attend_appel(p, appels, "POST", "/api/v1/webos/actions/torrent/ajouter")
    assert ("POST", "/api/v1/webos/actions/torrent/ajouter", '{"magnet":"magnet:?xt=urn:btih:abc"}') in appels
    p.locator("#items .it").first.locator("[data-a=pause]").click()
    attend_appel(p, appels, "POST", "/api/v1/webos/actions/torrent/pause")
    assert ("POST", "/api/v1/webos/actions/torrent/pause", '{"id":"h1"}') in appels and err == []
    ctx.close()


def test_quick_cloud_sans_session_le_dit_au_lieu_de_zeros(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "quick", "?svc=nextcloud", {"/adm/api/v1/nextcloud/status": (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert "connexion requise pour voir" in p.inner_text("#note") and p.inner_text("#etat") == "SESSION REQUISE"
    assert p.eval_on_selector_all("#tuiles .tuile .v", "els => els.map(e => e.textContent)") == ["—", "—"] and err == []
    ctx.close()


def test_quick_cloud_et_photos_etat_reel(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "quick", "?svc=nextcloud", {"/adm/api/v1/nextcloud/status": (200, {"running": False, "installed": True, "user_count": 2, "disk_used": "3 Go"})})
    p.wait_for_function("document.getElementById('note').textContent.includes('endormi')")
    assert p.eval_on_selector_all("#tuiles .tuile .v", "els => els.map(e => e.textContent)") == ["2", "3 Go"] and p.locator("#acces a").get_attribute("href") == "https://nc.gk2.secubox.in/sbx/entrer"
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "quick", "?svc=photoprism&embed=1", {"/adm/api/v1/photoprism/status": (200, {"container_status": "not_installed"})})
    p.wait_for_function("document.getElementById('note').textContent === 'non installé'")
    assert p.locator("#tuiles .tuile").count() == 0 and p.is_hidden("#hote") and p.is_visible("#nom") and err == []
    ctx.close()


def test_quick_demo_annoncee_et_toutes_les_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "quick", "?svc=depot&demo=1", {})
    p.wait_for_selector("#items .it")
    assert p.is_visible("#demo") and p.locator("#items .it").count() == 2
    p.locator("#items .it").first.get_by_text("✕").click()
    p.locator("#items .it").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('msg').textContent.includes('inerte')")
    p.set_input_files("#fich", {"name": "a.txt", "mimeType": "text/plain", "buffer": b"abc"})
    p.wait_for_selector("#go")
    p.click("#go")
    assert "inerte" in p.inner_text("#msg") and appels == [] and err == []
    ctx.close()
    ctx, p, err, appels = ouvre(navigateur, "quick", "?svc=torrent&demo=1", {})
    p.wait_for_selector("#mag")
    p.fill("#mag", "magnet:?x")
    p.click("#go")
    assert "inerte" in p.inner_text("#msg") and appels == [] and err == []
    ctx.close()


# ----- quifrappe -----

QF = {"ok": True, "attaquants": 18, "campagnes_total": 3, "haute_valeur": 7, "campagnes": [
    {"signature": "wp-login-a1f3", "outil": "scan", "attaquants": 9, "sondes": 400, "haute_valeur": 0},
    {"signature": "env<b>-9c2e", "outil": "", "attaquants": 6, "sondes": 100, "haute_valeur": 5}]}


def test_quifrappe_chiffres_campagnes_et_420(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "quifrappe", "", {"/api/v1/webos/public/waf/qui-frappe": (200, QF)}, {"width": 420, "height": 800})
    p.wait_for_selector("#camps .camp")
    assert textes(p, ["#v-att", "#v-camp", "#v-hv", "#etat"]) == ["18", "3", "7", "2 CAMPAGNES"]
    assert p.locator("#camps .camp").count() == 2 and "env<b>-9c2e" in p.inner_text("#camps") and p.locator("#camps b").count() == 0
    larges = p.eval_on_selector_all("#camps .barre i", "els => els.map(e => e.style.width)")
    assert larges == ["100%", "25%"]                              # proportionnel à la plus grosse campagne
    assert pas_de_debordement(p) and err == [] and hauteurs(p) and [a[0] for a in appels] == ["GET"]
    ctx.close()


def test_quifrappe_mesure_absente_est_un_tiret_et_zero_reste_zero(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "quifrappe", "", {"/api/v1/webos/public/waf/qui-frappe": (200, {"ok": True, "attaquants": 0, "campagnes": []})})
    p.wait_for_function("document.getElementById('etat').textContent === 'CALME'")
    assert textes(p, ["#v-att", "#v-camp", "#v-hv"]) == ["0", "—", "—"] and p.is_visible("#vide") and err == []
    ctx.close()


def test_quifrappe_waf_injoignable_et_demo(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "quifrappe", "", {})
    p.wait_for_function("document.getElementById('etat').textContent === 'SANS DONNÉE'")
    assert textes(p, ["#v-att", "#v-camp", "#v-hv"]) == ["—", "—", "—"] and p.is_visible("#vide") and err == []
    ctx.close()
    ctx, p, err, appels = ouvre(navigateur, "quifrappe", "?demo=1", {})
    p.wait_for_selector("#camps .camp")
    assert p.is_visible("#demo") and p.inner_text("#v-att") == "18" and appels == [] and err == []
    ctx.close()


def test_quifrappe_lien_du_pied_demande_au_hall_de_l_ouvrir(navigateur):
    ctx = navigateur.new_context(viewport={"width": 420, "height": 800})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "hote.html":
            r.fulfill(status=200, content_type="text/html", body="<iframe src='/cardlets/quifrappe.html' style='width:420px;height:300px'></iframe><script>window.m=[];addEventListener('message',e=>m.push(e.data))</script>")
        elif chemin == "cardlets/quifrappe.html":
            r.fulfill(status=200, content_type="text/html", body=(CARTES / "quifrappe.html").read_text(encoding="utf-8"))
        elif chemin in ("sonde.js", "domaine.js", "aide.js"):
            r.fulfill(status=200, content_type="application/javascript", body=(HALL / chemin).read_text(encoding="utf-8"))
        elif chemin.endswith("hotes.js"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin == "api/v1/webos/public/waf/qui-frappe":
            r.fulfill(status=200, content_type="application/json", body=json.dumps(QF))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/hote.html")
    f = p.frames[1]
    f.wait_for_selector("#camps .camp")
    f.click("#pied")
    p.wait_for_function("window.m.some(x => x && x.sbx === 'ouvre')")
    ms = p.evaluate("window.m")
    ouvre_msg = [x for x in ms if x.get("sbx") == "ouvre"][0]
    assert ouvre_msg["id"] == "quifrappe" and ouvre_msg["url"] == "https://waf.gk2.secubox.in/"
    assert [x for x in ms if "sbxVue" in x][-1]["onglet"] == "quifrappe" and erreurs == []
    ctx.close()


# ----- toutes les cartes -----

@pytest.mark.parametrize("nom,qs", [("freeboxtv", ""), ("ipv6guard", ""), ("lyrion", ""), ("metablog", ""), ("peertube", ""), ("quick", "?svc=depot"), ("quifrappe", "")])
def test_cas_vide_sans_api_aucune_erreur_js_et_pas_de_debordement_a_420(navigateur, nom, qs):
    ctx, p, err, _ = ouvre(navigateur, nom, qs, {}, {"width": 420, "height": 800})
    p.wait_for_timeout(600)
    assert err == [] and pas_de_debordement(p)
    ctx.close()


@pytest.mark.parametrize("nom,qs", [("freeboxtv", "?demo=1"), ("ipv6guard", "?demo=1"), ("lyrion", "?demo=1"), ("metablog", "?demo=1"), ("peertube", "?demo=1"),
                                    ("quick", "?svc=torrent&demo=1"), ("quifrappe", "?demo=1")])
def test_demo_a_420_sans_debordement_et_hauteur_annoncee(navigateur, nom, qs):
    ctx, p, err, appels = ouvre(navigateur, nom, qs, {}, {"width": 420, "height": 800})
    p.wait_for_selector("#demo:not([hidden])")
    p.wait_for_timeout(400)
    assert "DÉMONSTRATION" in p.inner_text("#demo")
    assert pas_de_debordement(p) and err == [] and appels == []
    assert hauteurs(p) and all(h >= 200 for h in hauteurs(p))
    # le texte ne sort d'aucune tuile ni d'aucun panneau
    assert p.evaluate("""[...document.querySelectorAll('.tuile,.pan,.verdict')].every(e => e.scrollWidth <= e.clientWidth + 1)""")
    ctx.close()

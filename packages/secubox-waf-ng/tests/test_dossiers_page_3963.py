# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3963 — /waf/sites.html : liste par urgence et dossier ; vrai navigateur, API simulée (sbx.test)."""
import json
import re
import time
from pathlib import Path

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
WWW = PAQUETS / "secubox-waf-ng" / "composants" / "waf" / "www" / "waf"
PAGE = (WWW / "sites.html").read_text(encoding="utf-8")
INDEX = (WWW / "index.html").read_text(encoding="utf-8")
XSS = "<img src=x onerror=window.xss=1>"


def _bloc(texte, debut, fin):
    return texte[texte.index(debut):texte.index(fin)]


# ── statique ───────────────────────────────────────────────────────────────────────────────────────────────────────

def test_un_script_en_ligne_aucune_dependance_aucun_balisage_injecte():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE
    assert len(re.findall(r"<script", PAGE)) == 1 and "<link" not in PAGE and "@import" not in PAGE
    for interdit in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval(", "confirm(", "alert(", "prompt(",
                     "POST", "http://", "scrollHeight", "100vh", "requestAnimationFrame", "lorem"):
        assert interdit not in PAGE.replace("http://www.w3.org/2000/svg", ""), interdit
    assert "sbxVue:" in PAGE and "onglet:'sites'" in PAGE and "/api/v1/waf/dossiers/sites" in PAGE
    assert not re.search(r"\son[a-z]+=", _bloc(PAGE, "<body>", "<script>"))


def test_textes_lisibles_et_cibles_tactiles():
    css = _bloc(PAGE, "<style>", "</style>")
    assert min(float(x) for x in re.findall(r"font-size:([0-9.]+)rem", css)) >= .85
    assert "min-height:40px" in css and "--faible" not in css and "prefers-reduced-motion:reduce" in css


def test_tronc_et_style_identiques_dans_le_soc():
    soc = (PAQUETS / "secubox-soc" / "www" / "soc" / "situations.html").read_text(encoding="utf-8")
    for debut, fin in (("/* ── style commun (dossiers) ── */", "/* ── fin du style commun ── */"),
                       ("// ── tronc commun (dossiers) ──", "// ── fin du tronc commun ──"), ("<body>", "<script>")):
        assert _bloc(PAGE, debut, fin) == _bloc(soc, debut, fin), debut


def test_premier_onglet_et_aucun_onglet_retire():
    onglets = re.findall(r'data-tab="([a-z]+)"', INDEX)
    assert onglets == ["sites", "vue", "overview", "attackers", "visits", "recon", "history", "campaigns", "decoys", "filtresia", "modes", "config"]
    assert "sites: 'sites'" in INDEX and 'switchTab("vue")' in INDEX and "'hashchange'" in INDEX


# ── navigateur ─────────────────────────────────────────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")
NOW = int(time.time())
DEB = (NOW // 3600 - 23) * 3600
NUL = [None] * 20


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def site(i, **k):
    return dict({"id": f"s{i}.exemple.test", "nom": f"s{i}.exemple.test", "titre": f"s{i}.exemple.test", "sous_titre": "18 requêtes hostiles · " + XSS,
                 "etiquettes": [["sous attaque", "r"], [XSS, 'x" onload="']], "urgence": 80 - i, "total": 18, "serie": NUL + [0, 5, 9, 4]}, **k)


def dossier(i, **k):
    def c(cle, nom, s):
        return {"cle": cle, "nom": nom, "def": "d", "serie": NUL + s}

    return dict(site(i), **dict({"disponible": True, "genere_le": NOW, "age_s": 3, "debut": DEB, "pas": 3600, "partielles": [20], "attaque": True,
                "phrase": f"18 requêtes hostiles en 24 h {XSS}.",
                "couches": [c("arrete", "Arrêté", [0, 3, 6, 2]), c("refuse", "Refusé", [0, 1, 1, 0]), c("detourne", "Détourné", [0, 0, 0, 0]), c("passe", "Laissé passer", [0, 1, 2, 2])],
                "chaine": [{"nom": "Requêtes reçues", "n": None, "cle": "recues"}, {"nom": "Jugées hostiles", "n": 18, "cle": "hostiles"}, {"nom": "Arrêté", "n": 11, "cle": "arrete"}],
                "categories": [{"cle": "sqli", "nom": "Injection SQL", "n": 18, "arrete": 13}],
                "origine": {"unite": "requêtes", "lignes": [{"nom": "Hébergeurs", "n": 18}]},
                "faits": [{"ts": NOW - 60, "texte": "Dernier bannissement : " + XSS, "preuve": "pare-feu"}],
                "geste": {"libelle": "Ouvrir les menaces", "href": "/waf/#overview", "note": "Rien à décider.", "genre": ""}}, **k))


def liste(n=3, **k):
    return dict({"disponible": True, "genere_le": NOW, "age_s": 3, "perime": False, "couverture_depuis": DEB, "heures_mesurees": 24, "journal": "ok",
                 "rattrapage": False, "hors_plafond": 0, "sites": [site(i) for i in range(n)], "calmes": ["calme.exemple.test"], "calmes_total": 1,
                 "chiffres": {"sites_proteges": 1310, "hostiles": 1000, "ecartees": 999, "passees": 1, "tenu_pct": 99.9, "sous_attaque": 1,
                              "series": {"ecartees": NUL + [1, 2, 3, 4], "passees": NUL + [0, 0, 0, 1]}}}, **k)


class Banc:
    def __init__(self, nav, reps=None, taille=(1280, 900), url="?embed=1", reduit=False, hote=False, fuseau="Europe/Paris"):
        self.reps, self.appels, self.erreurs, self.dehors = reps if reps is not None else {}, [], [], []
        self.ctx = nav.new_context(viewport={"width": taille[0], "height": taille[1]}, reduced_motion="reduce" if reduit else "no-preference",
                                   timezone_id=fuseau, locale="fr-FR")
        self.p = self.ctx.new_page()
        self.p.on("pageerror", lambda e: self.erreurs.append(str(e)))
        self.p.on("request", lambda r: self.dehors.append(r.url) if not r.url.startswith("http://sbx.test/") else None)
        self.p.route("http://sbx.test/**", self._sert)
        self.p.goto("http://sbx.test/waf/" + ("" if hote else "sites.html") + url)

    def _sert(self, r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1].split("#")[0]
        f = WWW / (u.split("?")[0][len("/waf/"):] or "index.html") if u.startswith("/waf/") else None
        if f is not None and f.is_file() and f.suffix == ".html":
            return r.fulfill(status=200, content_type="text/html", headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'self'"},
                             body=f.read_text(encoding="utf-8"))
        if not u.startswith("/api/"):
            return r.fulfill(status=404, body="")
        self.appels.append(r.request.method + " " + u)
        c = self.api(u)
        return r.fulfill(status=c if isinstance(c, int) else 200, content_type="application/json", body="{}" if isinstance(c, int) else json.dumps(c))

    def api(self, u):
        if u in self.reps:
            return self.reps[u]
        m = re.match(r"/api/v1/waf/dossiers/sites/(?:s(\d+)\.exemple|calme)", u)
        if m:
            return dossier(int(m.group(1) or 0), id=u.rsplit("/", 1)[1], titre=u.rsplit("/", 1)[1])
        return liste() if u == "/api/v1/waf/dossiers/sites" else 404

    def pret(self):
        self.p.wait_for_selector("#dossier h2")
        return self

    def fin(self):
        assert self.erreurs == [] and self.dehors == []
        self.ctx.close()


def attends(p, js, delai=5.0):
    """Attente par sondage : la CSP de la page interdit l'évaluation de chaîne de `wait_for_function`."""
    fin = time.time() + delai
    while time.time() < fin:
        if p.evaluate(js):
            return
        p.wait_for_timeout(25)
    raise AssertionError("jamais vrai : " + js)


def txt(p, sel):
    return p.inner_text(sel).replace(" ", " ").replace(" ", " ")


def test_liste_dossier_et_donnees_hostiles_inertes(nav):
    b = Banc(nav).pret()
    assert b.p.locator("#liste .item").count() == 3 and b.p.locator("#liste .item[aria-current=true]").count() == 1
    t = txt(b.p, "#dossier")
    assert XSS in t and b.p.evaluate("window.xss") is None and b.p.locator("#dossier img, #liste img").count() == 0
    assert b.p.locator(".etiq i").nth(1).get_attribute("class") in (None, "")                # classe de l'API hors liste : ignorée
    assert "Requêtes reçues\n—" in t and "Le mur, en 24 h" in t and "pare-feu" in t
    c = txt(b.p, "#chiffres")
    assert "1 310" in c and "99,9 %" in c and "999 sur 1 000" in c
    assert b.p.locator("#chiffres svg").count() == 2                                         # mini-série seulement où elle existe
    assert b.p.get_attribute("#geste", "href") == "/waf/#overview" and b.p.get_attribute("#geste", "target") == "_top"
    assert all(a.startswith("GET ") for a in b.appels)
    b.fin()


def test_heure_non_mesuree_dite_zero_dessine(nav):
    b = Banc(nav).pret()
    lab = b.p.get_attribute(".graphe", "aria-label").replace(" ", " ")
    assert "20 heures non mesurées" in lab and "Pic : 9" in lab
    assert b.p.locator(".graphe .col").count() == 24
    titres = [x.replace(" ", " ") for x in b.p.locator(".graphe .col title").all_text_contents()]
    assert sum(x.endswith("pas mesuré") for x in titres) == 20
    assert "total 0" in titres[20] and "heure mesurée en partie" in titres[20] and "arrêté 6" in titres[22] and "en cours" in titres[23]
    assert b.p.locator("#liste .item .mini").first.locator("rect").count() == 4
    b.fin()


def test_clavier(nav):
    b = Banc(nav).pret()
    b.p.focus("#liste .item")
    b.p.keyboard.press("ArrowDown")
    assert b.p.evaluate("document.activeElement.dataset.id") == "s1.exemple.test"
    b.p.keyboard.press("Enter")
    attends(b.p, "document.querySelector('#dossier h2')&&document.querySelector('#dossier h2').textContent==='s1.exemple.test'")
    assert b.p.evaluate("document.activeElement.dataset.id") == "s1.exemple.test"             # le focus reste sur la liste
    b.p.focus(".graphe")
    for _ in range(3):
        b.p.keyboard.press("ArrowLeft")
    assert "total 5" in txt(b.p, ".lecture")
    b.p.keyboard.press("ArrowRight")
    assert "total 9" in txt(b.p, ".lecture")
    b.fin()


def test_relecture_garde_selection_et_focus_sans_redessiner(nav):
    b = Banc(nav).pret()
    b.p.click("#liste .item >> nth=2")
    attends(b.p, "document.querySelector('#dossier h2')&&document.querySelector('#dossier h2').textContent==='s2.exemple.test'")
    b.p.evaluate("document.querySelector('#dossier h2').marque=1;document.querySelector('#liste .item:nth-child(2)').focus()")
    n = len(b.appels)
    b.p.evaluate("document.getElementById('rafraichir').click()")
    b.p.wait_for_timeout(400)
    assert len(b.appels) == n + 2 and b.p.evaluate("document.querySelector('#dossier h2').marque") == 1
    assert b.p.evaluate("document.activeElement.dataset.id") == "s1.exemple.test"
    b.fin()


def test_site_calme_et_site_demande_par_l_adresse(nav):
    b = Banc(nav, url="?embed=1&site=calme.exemple.test").pret()
    assert txt(b.p, "#dossier h2") == "calme.exemple.test"
    b.p.click("#liste .calmes summary")
    assert b.p.locator("#liste .calmes button[aria-current=true]").inner_text() == "calme.exemple.test"
    b.fin()


@pytest.mark.parametrize("statut,attendu,session", [(401, "session requise", True), (403, "session requise", True),
                                                    (404, "ne tient pas encore de relevé par site", False), (503, "WAF injoignable", False)])
def test_refus_et_absence_dits(nav, statut, attendu, session):
    b = Banc(nav, {"/api/v1/waf/dossiers/sites": statut})
    attends(b.p, "document.querySelector('#liste .vide')&&!document.querySelector('#liste .vide').textContent.startsWith('Chargement')")
    assert attendu in txt(b.p, "#liste") and b.p.locator("#session").is_visible() is session
    assert b.p.locator("#chiffres b").all_inner_texts() == ["—"] * 4
    b.fin()


def test_premier_releve_absent_et_mesure_partielle(nav):
    b = Banc(nav, {"/api/v1/waf/dossiers/sites": {"disponible": False, "genere_le": None, "couverture_depuis": None}})
    attends(b.p, "document.querySelector('#liste').textContent.includes('Premier relevé en cours')")
    b.fin()
    b = Banc(nav, {"/api/v1/waf/dossiers/sites": liste(journal="illisible", perime=True, age_s=7200, heures_mesurees=3, hors_plafond=2, rattrapage=True, sauts_24h=2, routes="illisible")}).pret()
    t = txt(b.p, "#alertes")
    for x in ("Journal des menaces illisible", "Relevé figé", "Mesure complète sur 3 heures sur 24", "2 événements non comptés", "Lecture du journal en retard", "2 passages ont été sautés", "Table des sites illisible"):
        assert x in t, x
    b.fin()


def test_dossier_muet_ou_lien_suspect(nav):
    b = Banc(nav, {"/api/v1/waf/dossiers/sites/s0.exemple.test": 503})
    attends(b.p, "document.querySelector('#dossier').textContent.includes('Dossier indisponible')")
    b.fin()
    for u in ("javascript:window.xss=1", "//ailleurs.test/", "https://ailleurs.test/"):
        b = Banc(nav, {"/api/v1/waf/dossiers/sites/s0.exemple.test": dossier(0, geste={"libelle": "x", "href": u, "note": "", "genre": "r"})}).pret()
        assert b.p.locator("#geste").count() == 0
        b.fin()


def test_noms_des_sites_calmes_reserves(nav):
    b = Banc(nav, {"/api/v1/waf/dossiers/sites": liste(calmes=[], calmes_total=12)}).pret()
    assert "12 sites sans événement (noms réservés à l’administrateur)" in txt(b.p, "#liste") and b.p.locator("#liste details").count() == 0
    b.fin()


def test_heures_de_paris_et_les_deux_2_h(nav):
    import datetime as dt
    deb = int(dt.datetime(2026, 10, 24, 12, tzinfo=dt.timezone.utc).timestamp())
    c = [{"cle": "arrete", "nom": "Arrêté", "serie": [1] * 24}]
    b = Banc(nav, {"/api/v1/waf/dossiers/sites/s0.exemple.test": dossier(0, debut=deb, couches=c, partielles=[])}, fuseau="America/New_York").pret()
    t = [x.replace("\u00a0", " ") for x in b.p.locator(".graphe .col title").all_text_contents()]
    assert t[0].startswith("14 h :") and t[12].startswith("2 h (été)") and t[13].startswith("2 h (hiver)") and t[14].startswith("3 h :")
    b.fin()


@pytest.mark.parametrize("largeur", [1280, 820, 400, 320])
def test_aucun_debordement(nav, largeur):
    long_ = "tres-long-nom-de-site-" * 5 + "exemple.test"
    b = Banc(nav, {"/api/v1/waf/dossiers/sites": liste(60, sites=[site(0, titre=long_)] + [site(i) for i in range(1, 60)]),
                   "/api/v1/waf/dossiers/sites/s0.exemple.test": dossier(0, titre=long_)}, taille=(largeur, 800)).pret()
    assert b.p.evaluate("document.documentElement.scrollWidth") <= largeur
    assert b.p.evaluate("[...document.querySelectorAll('button,.bouton')].filter(e=>e.offsetParent&&e.getBoundingClientRect().height<40).length") == 0
    assert b.p.locator("#liste .item").count() == 40                                        # liste bornée, le reste à la demande
    b.p.click("#liste .plus")
    assert b.p.locator("#liste .item").count() == 60 and b.p.evaluate("document.documentElement.scrollWidth") <= largeur
    b.fin()


def test_telephone_mene_au_dossier_et_retour(nav):
    b = Banc(nav, taille=(400, 800)).pret()
    b.p.click("#liste .item >> nth=1")
    attends(b.p, "document.activeElement.id==='dossier'")
    b.p.click("#retour")
    assert b.p.evaluate("document.activeElement.dataset.id") == "s1.exemple.test"
    b.fin()


def test_mouvement_reduit_rien_ne_bouge(nav):
    b = Banc(nav, reduit=True).pret()
    assert b.p.locator(".graphe rect.vif").count() > 0 and b.p.evaluate("document.getAnimations().length") == 0
    b.fin()


def test_demonstration_annoncee_sans_appel(nav):
    b = Banc(nav, url="?demo=1").pret()
    assert b.p.locator("#demo").is_visible() and b.appels == []
    b.fin()


def test_hote_ouvre_l_onglet_puis_suit_le_geste(nav):
    b = Banc(nav, url="?embed=1#sites:s1.exemple.test", hote=True)
    f = b.p.frame_locator("#pageFrame")
    f.locator("#dossier h2").wait_for()
    assert f.locator("#dossier h2").inner_text() == "s1.exemple.test"
    attends(b.p, "parseInt(document.getElementById('pageFrame').style.height)!==1200")
    f.locator("#geste").click()
    attends(b.p, "document.querySelector('[data-tab=overview]').getAttribute('aria-selected')==='true'")
    assert "menaces.html" in b.p.get_attribute("#pageFrame", "src")
    b.ctx.close()

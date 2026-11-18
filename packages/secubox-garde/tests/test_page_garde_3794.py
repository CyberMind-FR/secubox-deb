# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — page /garde/ : coque Aurora, tuiles, UNE carte par appareil, libérer confirmé, pas de débordement, CSP par hachage ;
page de quarantaine statique."""
import base64
import concurrent.futures
import hashlib
import json
import pathlib
import re

import pytest

RACINE = pathlib.Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "garde" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
CODE = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))
ISOLE = (RACINE / "www" / "garde" / "isole.html").read_text(encoding="utf-8")


def _hash(contenu):
    return "'sha256-" + base64.b64encode(hashlib.sha256(contenu.encode("utf-8")).digest()).decode() + "'"


def _csp(src):
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', src)
    assert m, "CSP absente"
    return m.group(1), {d.split()[0]: d.split()[1:] for d in (x.strip() for x in m.group(1).split(";")) if d}


def test_en_tete_titre_coque():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400] and "<title>Garde</title>" in SRC
    assert '<nav class="sidebar" id="sidebar"' in SRC and "sb.src='/shared/sidebar.js'" in CODE
    assert "if(EMB||DEMO)document.body.classList.add('emb');" in CODE and '<html lang="fr" class="sbx-aurora">' in SRC
    assert "localStorage.getItem('sbx_token')" in CODE and "credentials:'same-origin'" in CODE


def test_csp_stricte_par_hash_a_jour():
    brut, csp = _csp(SRC)
    scripts = re.findall(r"<script>(.*?)</script>", SRC, flags=re.S)
    assert len(scripts) == 1 and len(re.findall(r"<style>", SRC)) == 1
    assert csp["default-src"] == ["'self'"]
    assert csp["script-src"] == ["'self'", _hash(scripts[0])], "script modifié sans mise à jour de la CSP"
    assert csp["style-src"] == ["'self'", "'unsafe-inline'"] and "script-src-attr" not in csp
    assert not re.search(r"<[^>]+\son[a-z]+=", SRC)                         # aucun gestionnaire en attribut
    assert "unsafe-eval" not in brut and "http" not in brut
    assert ' style="' not in SRC and "<script " not in SRC


def test_aucun_innerhtml_ni_confirm_natif():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", CODE)
    assert not re.search(r"\b(confirm|alert|prompt)\(", CODE)
    assert CODE.count("method:'POST'") == 1 and "if(DEMO)return Promise.reject" in CODE


def test_routes_citees_existantes():
    from api import main
    existantes = {r.path.replace("/api/v1/garde", "", 1) for r in main.router.routes}
    citees = set(re.findall(r"(?:lire|ecrire)\('(/[a-z-]+)", CODE)) | set(re.findall(r"ecrire\(lib\?'(/[a-z]+)':'(/[a-z]+)'", CODE)[0])
    assert {"/etat", "/historique", "/reglages", "/liberer", "/rouvrir", "/debannir", "/cle-sms", "/tester"} <= citees
    assert citees <= existantes, citees - existantes


def test_quarantaine_statique_sans_bouton_ni_script():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in ISOLE[:400] and "Cet appareil est isolé" in ISOLE
    assert "<script" not in ISOLE and "<button" not in ISOLE and "<form" not in ISOLE and "<a " not in ISOLE
    brut, csp = _csp(ISOLE)
    assert csp["default-src"] == ["'none'"]
    assert csp["style-src"] == [_hash(re.findall(r"<style>(.*?)</style>", ISOLE, flags=re.S)[0])]


def test_installation():
    regles = (RACINE / "debian" / "rules").read_text(encoding="utf-8")
    assert "www/garde/index.html www/garde/isole.html $(P)/usr/share/secubox/www/garde/" in regles
    assert json.loads((RACINE / "menu.d" / "706-garde.json").read_text(encoding="utf-8"))["path"] == "/garde/"


# ── Playwright ──
sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"
ETAT = {"automatique": True, "quarantaines_max": 3, "releve": 1794980000, "session_requise": False,
        "tuiles": {"isoles": 1, "evasions": 1, "bannis": 2, "recidivistes": 1, "notifs_24h": {"sms": 2, "courriel": 3}, "en_attente": 1},
        "actives": [
            {"id": "d1", "menace": "infection", "nom": HOSTILE, "mac": "02:00:5e:00:00:95", "adresses": ["192.0.2.95", "2001:db8::95"],
             "motif": "serveur de pirates connu", "noms": [], "debut": 1794979000, "fin": 1795065000, "en_cours": False},
            {"id": "d2", "menace": "evasion", "nom": "Téléphone", "mac": "02:00:5e:00:00:42", "adresses": ["192.0.2.42"],
             "motif": "DoH", "noms": ["dns.example"], "debut": 1794979000, "fin": 1795065000, "en_cours": True},
            {"menace": "intrusion", "n": 2, "derniere": {"ip": "203.0.113.9", "debut": 1794979900},
             "adresses": [{"ip": "203.0.113.9", "fin": 1794990000, "recidive": True}, {"ip": "198.51.100.7", "fin": 1794990000}]}]}
HISTO = {"heures": 24, "lignes": [{"menace": "signale", "debut": 1794979000, "nom": "Tablette", "motif": "DGA"}]}
REG = {"automatique": True, "courriel": "a@example.org", "sms_utilisateur": "1234", "sms_bans": False,
       "cle_sms_enregistree": True, "cle_sms_en_attente": False, "en_attente": None}


def _page(scenario, largeur=1400, chemin="/garde/"):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page(viewport={"width": largeur, "height": 900})
            erreurs, posts = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u = route.request.url
                if route.request.method == "POST":
                    posts.append((u, route.request.post_data))
                    return route.fulfill(status=200, content_type="application/json", body='{"etat":"en_attente"}')
                corps = HISTO if "/historique" in u else REG if "/reglages" in u else ETAT
                route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
            pg.route("http://t.test/api/**", api)
            pg.route("http://t.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
            pg.route("http://t.test/garde/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto("http://t.test" + chemin)
            pg.wait_for_timeout(500)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, posts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def test_tuiles_et_une_carte_par_appareil():
    def sc(pg):
        return (pg.inner_text("#tuiles"), pg.eval_on_selector_all(".dec", "c => c.map(x => x.className)"),
                pg.inner_text(".dec.infection"), pg.inner_text("#alarme"), pg.evaluate("window.xss"))
    (tuiles, classes, inf, alarme, xss), erreurs, _p = _page(sc)
    assert not erreurs and xss is None
    assert "Appareils isolés\n1" in tuiles and "dont 1 récidiviste" in tuiles and "2 SMS · 3 courriels · 1 en attente" in tuiles
    assert classes == ["dec infection", "dec evasion", "dec intrusion"]          # une carte par appareil, bans groupés
    assert HOSTILE in inf and "192.0.2.95 · 2001:db8::95" in inf and "1 appareil isolé" in alarme


def test_liberer_demande_confirmation():
    def sc(pg):
        pg.click(".dec.infection >> text=Libérer")
        texte = pg.inner_text(".dec.infection .confirm")
        pg.click(".dec.infection >> text=Confirmer")
        pg.wait_for_timeout(300)
        return texte, pg.inner_text("#message")
    (texte, msg), erreurs, posts = _page(sc)
    assert "Pas de nouvelle mesure 7 j" in texte and not erreurs
    assert len(posts) == 1 and posts[0][0].endswith("/api/v1/garde/liberer") and json.loads(posts[0][1]) == {"id": "d1"}
    assert "prochain passage" in msg


def test_annuler_n_envoie_rien_et_en_cours_affiche():
    def sc(pg):
        pg.click(".dec.infection >> text=Libérer")
        pg.click(".dec.infection >> text=Annuler")
        return pg.inner_text(".dec.evasion"), pg.query_selector(".dec.infection .confirm")
    (eva, conf), erreurs, posts = _page(sc)
    assert not posts and conf is None and "levée en cours" in eva and not erreurs


def test_debannir_depuis_la_liste():
    def sc(pg):
        pg.click("text=Voir la liste")
        pg.click(".liste >> text=Débannir >> nth=0")
        pg.click(".liste >> text=Confirmer")
        pg.wait_for_timeout(300)
    _r, erreurs, posts = _page(sc)
    assert not erreurs and json.loads(posts[0][1]) == {"ip": "203.0.113.9"} and posts[0][0].endswith("/debannir")


def test_reglages_cle_jamais_affichee():
    def sc(pg):
        pg.click("#t-reglages")
        pg.wait_for_timeout(300)
        ph = pg.get_attribute("#r-cle", "placeholder")
        pg.fill("#r-cle", "AbC123")
        pg.click("#enregistrer")
        pg.wait_for_timeout(300)
        return ph, pg.input_value("#r-courriel")
    (ph, courriel), erreurs, posts = _page(sc)
    assert ph == "clé enregistrée ••••" and courriel == "a@example.org" and not erreurs
    assert [u.rsplit("/", 1)[1] for u, _ in posts] == ["reglages", "cle-sms"] and json.loads(posts[1][1]) == {"cle": "AbC123"}


MESURE = "() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]"


@pytest.mark.parametrize("largeur", [1400, 420])
def test_aucun_debordement_horizontal(largeur):
    def sc(pg):
        m = {}
        pg.click("text=Voir la liste")
        for o in ("decisions", "historique", "reglages"):
            pg.click(f"#t-{o}")
            pg.wait_for_timeout(200)
            m[o] = pg.evaluate(MESURE)
        return m
    (m, erreurs, _p) = _page(sc, largeur=largeur)
    trop = {o: v for o, v in m.items() if v[0] > v[1]}
    assert not trop and not erreurs, trop


def test_demo_sans_ecriture_ni_menu():
    def sc(pg):
        pg.click(".dec.infection >> text=Libérer")
        pg.click(".dec.infection >> text=Confirmer")
        pg.wait_for_timeout(200)
        return pg.inner_text("#message"), pg.is_visible("#demo")
    (msg, demo), erreurs, posts = _page(sc, chemin="/garde/?demo=1")
    assert demo and "démonstration" in msg and not posts and not erreurs


COQUE = RACINE.parent / "secubox-hub" / "www" / "shared"
MENU = json.dumps({"categories": [{"name": "Sécurité", "icon": "S", "items": [{"path": "/garde/", "name": "Garde", "icon": "G"}]}]})


@pytest.mark.parametrize("largeur", [1400, 420])
def test_aucun_debordement_avec_le_vrai_menu_lateral(largeur):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page(viewport={"width": largeur, "height": 900})
            erreurs = []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def partage(route):
                f = COQUE / route.request.url.split("/shared/", 1)[1].split("?")[0]
                if not f.is_file():
                    return route.fulfill(status=404, body="")
                route.fulfill(status=200, body=f.read_bytes(), content_type="text/javascript" if f.suffix == ".js" else "text/css")
            pg.route("http://t.test/shared/**", partage)
            pg.route("http://t.test/api/**", lambda r: r.fulfill(status=200, content_type="application/json",
                                                                 body=MENU if "/hub/public/menu" in r.request.url else json.dumps(ETAT)))
            pg.route("http://t.test/garde/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto("http://t.test/garde/")
            pg.wait_for_timeout(1200)
            m = {}
            for o in ("decisions", "historique", "reglages"):
                pg.click(f"#t-{o}")
                pg.wait_for_timeout(150)
                m[o] = pg.evaluate(MESURE)
            nav.close()
            return ("ok", m, erreurs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    m, erreurs = res[1:]
    trop = {o: v for o, v in m.items() if v[0] > v[1]}
    assert not trop and not erreurs, (trop, erreurs)

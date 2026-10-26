# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — onglet « Mode routeur » (routeur.html) : application asynchrone et compte à rebours réel.

Tests statiques (§ 11.1 du profil Aurora) puis vrai navigateur si Playwright est installé :
- démonstration complète à 1400 et 420 px (aperçu, confirmation intégrée, bascule, à confirmer, confirmer, retour), sans
  aucune requête, sans débordement ni erreur JS ;
- API simulée : 202 → « bascule en cours » relue toutes les 3 s → compte à rebours jusqu'à `echeance` (jamais
  `depuis` + 180) → Confirmer → actif → retour ; corps envoyés sans `wan` ; aucune actualisation pendant une confirmation
  ouverte ; écart d'horloge de la box corrigé ; session absente et source en panne jamais prises pour un état."""
import concurrent.futures
import email.utils
import ipaddress
import json
import re
import time
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
WWW = ICI / "www" / "netmodes"
PAGE = WWW / "routeur.html"
SRC = PAGE.read_text(encoding="utf-8")
DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
LECTURES = ["/api/v1/netmodes/routeur/etat", "/api/v1/netmodes/routeur/derniere"]
ECRITURES = ["/api/v1/netmodes/routeur/apercu", "/api/v1/netmodes/routeur/appliquer",
             "/api/v1/netmodes/routeur/confirmer", "/api/v1/netmodes/routeur/retour"]
CLES_CONFIG = {"adresse", "dhcp_debut", "dhcp_fin", "bail", "ports"}


def _code(s):
    """Le script sans commentaires (HTML et //)."""
    return re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", s, flags=re.S))


# ── Statique ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_page_autonome_sans_dependance_ni_boite_native():
    s = SRC
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert re.findall(r"<script[^>]*\bsrc=", s) == []
    assert re.findall(r"\.src\s*=\s*['\"]([^'\"]+)['\"]", s) == ["/shared/sidebar.js"]   # le menu commun, seul…
    assert re.search(r"if \(EMB \|\| DEMO\)", s)                                          # … hors ?embed=1 et hors démo
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "fonts.googleapis", "hybrid-skin",
                     "Math.random", "eval(", "new Function"):
        assert interdit not in s, interdit
    code = _code(s)
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "lorem" not in s.lower()
    assert "@container a" in s and "container-type:inline-size" in s
    assert "sbxVue" in s and "getBoundingClientRect().bottom" in s and "location.origin" in s
    assert 'var ONGLET = "routeur";' in s and "onglet: ONGLET" in s
    assert "scrollHeight" not in s and "100vh" not in s
    assert 'localStorage.getItem("sbx_token")' in s and "setItem" not in s and "Bearer " in s
    assert 'role="alertdialog"' in s and "focus-visible" in s


def test_demo_avec_adresses_de_documentation_seulement():
    assert "demo" in SRC and "DÉMONSTRATION" in SRC
    for ip in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", SRC):
        assert any(ipaddress.ip_address(ip) in n for n in DOC), ip
    assert "gk2.secubox" not in SRC and "secubox.in" not in SRC and "192.168." not in SRC


def test_routes_de_lecture_et_d_ecriture_citees():
    for r in LECTURES + ECRITURES:
        assert r in SRC, r
    code = _code(SRC)
    assert 'envoi.confirmer = "routeur";' in code                      # appliquer : la confirmation exigée par l'API
    assert 'ecrireEtat("retour", { confirmer: "retour" })' in code
    assert 'method: "POST"' in code and 'method: "GET"' in code and code.count("fetch(") == 2
    # démonstration : aucune requête, les écritures passent par la simulation
    assert "if (DEMO) { return Promise.resolve(demoEcrire(quoi, corps)); }" in code


def test_jamais_wan_envoye_ni_compte_depuis_l_application():
    code = _code(SRC)
    m = re.search(r"function corps\(\) \{(.*?)\n  \}", code, flags=re.S)
    assert m, "corps() introuvable"
    corps = m.group(1)
    assert "wan" not in corps
    for k in ("adresse:", "dhcp_debut:", "dhcp_fin:", "ports:", "c.bail = b"):
        assert k in corps, k
    # le corps d'appliquer = corps() + confirmer, rien d'autre
    assert "Object.keys(a.corps).forEach(function (k) { envoi[k] = a.corps[k]; });" in code
    # compte à rebours : l'échéance du minuteur, jamais `depuis` + 180
    assert "Date.parse(e.echeance)" in code
    for ligne in code.splitlines():
        assert not ("depuis" in ligne and re.search(r"\b180\b", ligne)), ligne
    # cadence : 3 s pendant une bascule, page visible seulement, jamais pendant une confirmation ouverte
    assert "RAPIDE = 3000" in code and "document.hidden" in code and "confirmationOuverte()" in code


def test_rappels_eth2_webfilter_et_garde():
    assert "eth2 n'est jamais touché" in SRC
    assert "[reseau].lan" in SRC and "webfilter.toml" in SRC
    assert "une bascule lente (Unbound) continue même si le navigateur perd la connexion : la garde de 3 minutes protège" in SRC
    assert "échéance inconnue" in SRC


# ── Navigateur ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _avec_navigateur(scenario):
    sync_api = pytest.importorskip("playwright.sync_api")

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:      # navigateur absent : test sauté, pas en échec
                return ("skip", str(e))
            try:
                return ("ok", scenario(nav))
            finally:
                nav.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=300)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1]


def _page(nav, api=None, taille=(1400, 900)):
    """Pages servies par une origine http fictive ; `api` : chemin -> (statut, corps[, en-têtes]) ou fonction(méthode, corps).
    Une fonction qui rend None garde la requête en suspens (j["gardees"]) : le scénario y répondra plus tard."""
    ctx = nav.new_context(viewport={"width": taille[0], "height": taille[1]})
    pg = ctx.new_page()
    j = {"erreurs": [], "natifs": [], "appels": [], "gardees": []}
    pg.on("pageerror", lambda e: j["erreurs"].append(str(e)))
    pg.on("dialog", lambda d: (j["natifs"].append(d.type), d.dismiss()))

    def servir(r):
        chemin = r.request.url.split("http://t.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("api/"):
            corps = r.request.post_data
            j["appels"].append((r.request.method, chemin, json.loads(corps) if corps else None, time.time()))
            rep = (api or {}).get(chemin[len("api/v1/"):], (404, {"detail": "absent"}))
            if callable(rep):
                rep = rep(r.request.method, json.loads(corps) if corps else None)
                if rep is None:                      # réponse retardée : le scénario la donnera
                    j["gardees"].append(r)
                    return None
            st, b = rep[0], rep[1]
            entetes = rep[2] if len(rep) > 2 else {}
            return r.fulfill(status=st, content_type="application/json", body=json.dumps(b), headers=entetes or None)
        if chemin.startswith("netmodes/"):
            f = WWW / (chemin.split("/", 1)[1] or "index.html")
            if f.is_file():
                return r.fulfill(status=200, content_type="text/html", body=f.read_text(encoding="utf-8"))
        r.fulfill(status=404, content_type="text/plain", body="absent")
    pg.route("http://t.test/**", servir)
    return ctx, pg, j


def _sans_debordement(page_ou_cadre):
    return page_ou_cadre.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def _pastille(pg, texte, delai=12000):
    pg.wait_for_function("t => document.getElementById('pastille').textContent === t", arg=texte, timeout=delai)


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


@pytest.mark.parametrize("largeur", [1400, 420])
def test_demo_enchainement_complet_sans_aucune_requete(largeur):
    def scenario(nav):
        ctx, pg, j = _page(nav, taille=(largeur, 900))
        r = {"deb": []}
        pg.goto("http://t.test/netmodes/routeur.html?demo=1")
        _pastille(pg, "LAN TEMPORAIRE")
        r["prerempli"] = [pg.input_value(i) for i in ("#fAdresse", "#fDebut", "#fFin", "#fBail")]
        r["coupe"] = pg.is_visible("#c-lan2")
        r["retour_cache"] = pg.is_hidden("#btnRetour")
        r["deb"].append(_sans_debordement(pg))
        # aperçu sur le même réseau : pas d'avertissement ; sur un autre : avertissement, rendu en texte
        pg.click("#btnApercu")
        pg.wait_for_selector("#apercu details")
        r["fichiers"] = pg.locator("#apercu details").count()
        r["avert_meme"] = pg.locator("#apercu .alerte").count()
        pg.fill("#fAdresse", "192.0.2.1/24")
        pg.fill("#fDebut", "192.0.2.100")
        pg.fill("#fFin", "192.0.2.199")
        r["apercu_oublie"] = pg.locator("#apercu details").count()          # valeurs changées : l'ancien aperçu disparaît
        pg.click("#btnAppliquer")                                             # aperçu automatique, puis confirmation
        pg.wait_for_selector("#confirmApp:not([hidden])")
        r["confirmation"] = pg.inner_text("#confirmApp")
        pg.click("#confirmAppNon")
        pg.wait_for_selector("#confirmApp[hidden]", state="attached")
        pg.wait_for_timeout(300)
        r["annule"] = pg.inner_text("#pastille")
        pg.click("#btnAppliquer")
        pg.wait_for_selector("#confirmApp:not([hidden])")
        pg.click("#confirmAppOk")
        _pastille(pg, "BASCULE EN COURS", 3000)
        r["bascule"] = (pg.inner_text("#phaseTitre"), pg.is_disabled("#btnAppliquer"), pg.inner_text("#derniere"))
        r["deb"].append(_sans_debordement(pg))
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        r["compte"] = pg.inner_text("#phaseCompte")
        r["tuile"] = pg.inner_text("#tRetour")
        r["confirmer_visible"] = pg.is_visible("#btnConfirmer")
        r["deb"].append(_sans_debordement(pg))
        pg.click("#btnConfirmer")
        _pastille(pg, "MODE ROUTEUR ACTIF", 4000)
        r["actif"] = (pg.inner_text("#phaseTitre"), pg.inner_text("#tRetour"), pg.inner_text("#derniere"), pg.input_value("#fAdresse"))
        pg.click("#btnRetour")
        pg.wait_for_selector("#confirmRetour:not([hidden])")
        r["confirm_retour"] = pg.inner_text("#confirmRetour")
        pg.click("#confirmRetourOk")
        _pastille(pg, "BASCULE EN COURS", 3000)
        _pastille(pg, "LAN TEMPORAIRE")
        r["fin"] = pg.inner_text("#derniere")
        r["deb"].append(_sans_debordement(pg))
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["prerempli"] == ["198.51.100.1/24", "198.51.100.100", "198.51.100.199", "12h"] and r["coupe"] and r["retour_cache"]
    assert r["fichiers"] == 7 and r["avert_meme"] == 0 and r["apercu_oublie"] == 0
    assert "192.0.2.1/24" in r["confirmation"] and "perdrez la connexion" in r["confirmation"] and "eth2 n'est jamais touché" in r["confirmation"]
    assert r["annule"] == "LAN TEMPORAIRE"                                    # Annuler : rien de lancé
    titre, desactive, derniere = r["bascule"]
    assert titre.startswith("Bascule en cours") and desactive and "en cours" in derniere
    assert re.fullmatch(r"(2 min [45]\d s|3 min 00 s)", r["compte"]), r["compte"]
    assert r["tuile"] == r["compte"] and r["confirmer_visible"]
    titre, tuile, derniere, adresse = r["actif"]
    assert titre == "Mode routeur actif" and tuile == "—" and "réussie" in derniere and adresse == "192.0.2.1/24"
    assert "dernière sauvegarde" in r["confirm_retour"] and "Retour en arrière" in r["fin"]
    assert all(r["deb"])
    assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == []    # démonstration : aucune requête, donc aucune écriture


@pytest.mark.parametrize("largeur", [1400, 420])
def test_hote_onglet_routeur_hauteur_annoncee_sans_debordement(largeur):
    def scenario(nav):
        ctx, pg, j = _page(nav, taille=(largeur, 900))
        pg.goto("http://t.test/netmodes/index.html?demo=1#routeur")
        pg.wait_for_function("document.getElementById('vue').style.height !== '1000px'", timeout=8000)
        pg.wait_for_timeout(400)
        cadre = pg.query_selector("#vue").content_frame()
        r = (pg.get_attribute("#vue", "src"), pg.evaluate("parseInt(document.getElementById('vue').style.height)"),
             _sans_debordement(pg), _sans_debordement(cadre), cadre.inner_text("#pastille"), cadre.is_visible("#sidebar"))
        ctx.close()
        return r, j
    (src, h, page_ok, cadre_ok, pastille, menu), j = _avec_navigateur(scenario)
    assert src == "routeur.html?embed=1&demo=1" and 300 <= h <= 4000 and h != 1000
    assert page_ok and cadre_ok and pastille == "LAN TEMPORAIRE" and not menu
    assert j["erreurs"] == [] and j["appels"] == []


# ── API simulée : la vraie suite d'appels ────────────────────────────────────────────────────────────────────────────────────────
CONFIG = {"adresse": "198.51.100.1/24", "dhcp_debut": "198.51.100.100", "dhcp_fin": "198.51.100.199", "bail": "12h",
          "ports": ["lan0", "lan1", "lan3"], "wan": "eth2"}
XSS = "<img src=x onerror=alert(1)>"


def _etat(**kw):
    d = {"etat": "inactif", "depuis": None, "acteur": "admin", "sauvegarde": None, "config": CONFIG, "minuteur_actif": False,
         "echeance": None, "bascule_en_cours": False, "dhcp_actif": True, "adresses_pont": ["198.51.100.1/24"], "ports_coupes": ["lan2"]}
    d.update(kw)
    return d


VIDE = {"verbe": None, "code": None, "sortie": None, "fini": True, "debut": None, "fin": None}


class Box:
    """Le contrôleur vu de l'API : une bascule dure trois lectures d'état, puis attend sa confirmation 100 s."""

    def __init__(self):
        self.phase, self.lus, self.verbe, self.debut, self.fin, self.echeance = "inactif", 0, None, None, None, None

    def etat(self, _m, _c):
        if self.phase in ("bascule", "retour"):
            self.lus += 1
            if self.lus > 2:
                self.fin = _iso(time.time())
                if self.phase == "bascule":
                    self.phase, self.echeance = "attente", time.time() + 100
                else:
                    self.phase = "inactif"
        if self.phase == "bascule":
            return 200, _etat(etat="en_attente", depuis=_iso(time.time() - 150), bascule_en_cours=True)
        if self.phase == "retour":
            return 200, _etat(etat="actif", bascule_en_cours=True)
        if self.phase == "attente":    # depuis + 180 donnerait 30 s : la page doit compter jusqu'à l'échéance (100 s)
            return 200, _etat(etat="en_attente", depuis=_iso(time.time() - 150), minuteur_actif=True, echeance=_iso(self.echeance),
                              adresses_pont=["192.0.2.1/24"])
        if self.phase == "actif":
            return 200, _etat(etat="actif", depuis=_iso(time.time()), adresses_pont=["192.0.2.1/24"])
        return 200, _etat()

    def derniere(self, _m, _c):
        if self.verbe is None:
            return 200, VIDE
        cours = self.phase in ("bascule", "retour")
        return 200, {"verbe": self.verbe, "code": None if cours else 200, "fini": not cours, "debut": self.debut,
                     "sortie": None if cours else {"etat": "en_attente", "delai_confirmation": 180}, "fin": None if cours else self.fin}

    def apercu(self, _m, _c):
        return 200, {"fichiers": {"netdev": "[NetDev]\nName=br-lan\n", "nft": "# " + XSS + "\n"},
                     "avertissement": "Vous appliquez depuis le LAN actuel : vous perdrez la connexion ; confirmez depuis la nouvelle adresse sous 3 minutes."}

    def lancer(self, phase, verbe):
        self.phase, self.lus, self.verbe, self.debut = phase, 0, verbe, _iso(time.time())
        return 202, {"lancee": True}

    def api(self):
        return {"netmodes/routeur/etat": self.etat, "netmodes/routeur/derniere": self.derniere, "netmodes/routeur/apercu": self.apercu,
                "netmodes/routeur/appliquer": lambda m, c: self.lancer("bascule", "routeur-appliquer"),
                "netmodes/routeur/confirmer": lambda m, c: (setattr(self, "phase", "actif"), (200, _etat(etat="actif")))[1],
                "netmodes/routeur/retour": lambda m, c: self.lancer("retour", "routeur-retour")}


def test_202_bascule_relue_toutes_les_3_s_puis_compte_jusqu_a_l_echeance_reelle():
    box = Box()

    def scenario(nav):
        ctx, pg, j = _page(nav, box.api())
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "LAN TEMPORAIRE")
        r = {"prerempli": [pg.input_value(i) for i in ("#fAdresse", "#fBail")] + [pg.is_checked("#p-lan2"), pg.is_checked("#p-lan3")]}
        pg.click("#btnApercu")
        pg.wait_for_selector("#apercu details")
        r["apercu"] = (pg.inner_text("#apercu"), pg.locator("img").count())
        pg.locator("#apercu details").nth(1).locator("summary").click()
        r["nft"] = pg.inner_text("#apercu details:nth-of-type(2) pre")
        pg.click("#btnAppliquer")                                   # aperçu des mêmes valeurs déjà fait : confirmation directe
        pg.wait_for_selector("#confirmApp:not([hidden])")
        r["confirmation"] = pg.inner_text("#confirmApp")
        pg.click("#confirmAppOk")
        _pastille(pg, "BASCULE EN COURS", 3000)
        r["resultat"] = pg.inner_text("#resultatBascule")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER", 15000)
        r["compte"] = pg.inner_text("#phaseCompte")
        r["texte"] = pg.inner_text("#phaseTexte")
        pg.click("#btnConfirmer")
        _pastille(pg, "MODE ROUTEUR ACTIF", 4000)
        r["confirme"] = pg.inner_text("#resultatBascule")
        pg.click("#btnRetour")
        pg.wait_for_selector("#confirmRetour:not([hidden])")
        pg.click("#confirmRetourOk")
        _pastille(pg, "BASCULE EN COURS", 3000)
        _pastille(pg, "LAN TEMPORAIRE", 15000)
        r["img"] = pg.locator("img").count()
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["prerempli"] == ["198.51.100.1/24", "12h", False, True]           # ports de la config ; lan2 hors du pont
    texte_apercu, imgs = r["apercu"]
    assert "perdrez la connexion" in texte_apercu and imgs == 0 and XSS in r["nft"]
    assert "perdrez la connexion" in r["confirmation"]
    assert "202" in r["resultat"]
    assert re.fullmatch(r"1 min (3\d|40) s", r["compte"]), r["compte"]          # échéance (100 s), pas depuis + 180 (30 s)
    assert "revient d'elle-même" in r["texte"]
    assert "confirmé" in r["confirme"] and r["img"] == 0

    posts = [(c[1].rsplit("/", 1)[1], c[2]) for c in j["appels"] if c[0] == "POST"]
    assert [p[0] for p in posts] == ["apercu", "appliquer", "confirmer", "retour"]
    apercu, appliquer, confirmer, retour = (p[1] for p in posts)
    assert set(apercu) == CLES_CONFIG and "wan" not in apercu                    # jamais `wan`, même lu dans etat.config
    assert apercu == {"adresse": "198.51.100.1/24", "dhcp_debut": "198.51.100.100", "dhcp_fin": "198.51.100.199", "bail": "12h", "ports": ["lan0", "lan1", "lan3"]}
    assert appliquer == dict(apercu, confirmer="routeur")
    assert confirmer is None and retour == {"confirmer": "retour"}
    # pendant la bascule, l'état est relu toutes les 3 s
    t_app = next(c[3] for c in j["appels"] if c[1].endswith("/appliquer"))
    t_conf = next(c[3] for c in j["appels"] if c[1].endswith("/confirmer"))
    lectures = [c[3] for c in j["appels"] if c[0] == "GET" and c[1].endswith("/etat") and t_app < c[3] < t_conf]
    ecarts = [b - a for a, b in zip(lectures, lectures[1:])]
    assert len(lectures) >= 3 and all(2.5 <= e <= 4.5 for e in ecarts[:2]), ecarts
    assert j["erreurs"] == [] and j["natifs"] == []


def test_aucune_actualisation_pendant_une_confirmation_ouverte_et_echeance_inconnue():
    api = {"netmodes/routeur/etat": (200, _etat(etat="en_attente", depuis=_iso(time.time() - 20), minuteur_actif=False, echeance=None)),
           "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")

        def n():
            return sum(1 for c in j["appels"] if c[1].endswith("/etat"))
        pg.wait_for_timeout(3600)
        r = {"rapide": n(), "compte": pg.inner_text("#phaseCompte"), "tuile": pg.inner_text("#tRetour"), "sous": pg.inner_text("#tRetourS"),
             "texte": pg.inner_text("#phaseTexte")}
        pg.click("#btnRetour")
        pg.wait_for_selector("#confirmRetour:not([hidden])")
        avant = n()
        pg.wait_for_timeout(4500)
        r["pendant"] = n() - avant
        pg.click("#confirmRetourNon")
        pg.wait_for_timeout(3800)
        r["apres"] = n() - avant
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["rapide"] >= 2                                         # « à confirmer » sans minuteur : relu toutes les 3 s
    assert r["compte"] == "échéance inconnue" and r["tuile"] == "—" and r["sous"] == "aucun minuteur armé"
    assert "non armé" in r["texte"]
    assert r["pendant"] == 0 and r["apres"] >= 1                   # rien pendant la confirmation, reprise ensuite
    assert not any(c[0] == "POST" for c in j["appels"]) and j["erreurs"] == []


def test_ecart_d_horloge_de_la_box_corrige_par_l_en_tete_date():
    """Poste en retard d'une heure : l'échéance (heure de la box) est comptée sur l'heure de la box, pas celle du poste."""
    def etat(_m, _c):
        boite = time.time() + 3600
        return 200, _etat(etat="en_attente", minuteur_actif=True, echeance=_iso(boite + 120)), {"Date": email.utils.formatdate(boite, usegmt=True)}
    api = {"netmodes/routeur/etat": etat, "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        pg.wait_for_timeout(300)
        r = (pg.inner_text("#phaseCompte"), pg.inner_text("#phaseTexte"), pg.inner_text("#tRetourS"))
        ctx.close()
        return r, j
    (compte, texte, sous), j = _avec_navigateur(scenario)
    assert re.fullmatch(r"(1 min 5\d s|2 min 0[01] s)", compte), compte          # sans correction : « 1 h 02 min »
    assert "heure de la box" in texte and "heure de la box" in sous and j["erreurs"] == []


def test_session_absente_et_source_en_panne_jamais_deduites():
    def scenario(nav):
        r = {}
        ctx, pg, j = _page(nav, {"netmodes/routeur/etat": (401, {"detail": "Not authenticated"}),
                                 "netmodes/routeur/derniere": (401, {"detail": "Not authenticated"})})
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "SESSION REQUISE")
        r["session"] = ([pg.inner_text(i) for i in ("#tEtat", "#tRetour", "#tPont", "#tDhcp")], pg.is_visible("#session"),
                        pg.input_value("#fAdresse"), pg.is_hidden("#btnConfirmer"), pg.is_hidden("#btnRetour"), pg.inner_text("#derniere"))
        ctx.close()
        ctx, pg, j2 = _page(nav, {"netmodes/routeur/etat": (502, {"detail": "contrôleur réseau injoignable"}),
                                  "netmodes/routeur/derniere": (200, {"verbe": "routeur-appliquer", "code": 502, "fini": True,
                                                                      "sortie": {"erreur": XSS}, "debut": "2026-10-26T15:00:00Z", "fin": "2026-10-26T15:00:40Z"}),
                                  "netmodes/routeur/apercu": (400, {"detail": "dhcp_debut 192.0.2.5 est hors du réseau 198.51.100.0/24"})})
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "ÉTAT DU ROUTEUR ILLISIBLE")
        pg.fill("#fAdresse", "198.51.100.1/24")
        pg.fill("#fDebut", "192.0.2.5")
        pg.fill("#fFin", "198.51.100.9")
        pg.click("#btnAppliquer")                                    # l'aperçu refusé n'ouvre pas la confirmation
        pg.wait_for_selector("#resultatConfig:not([hidden])")
        r["panne"] = (pg.inner_text("#phaseTexte"), pg.inner_text("#tEtat"), pg.inner_text("#derniere"), pg.locator("img").count(),
                      pg.inner_text("#resultatConfig"), pg.is_hidden("#confirmApp"), pg.inner_text("#sources"))
        ctx.close()
        return r, j["erreurs"] + j2["erreurs"] + j["natifs"] + j2["natifs"], j2["appels"]
    r, erreurs, appels = _avec_navigateur(scenario)
    tuiles, bandeau, adresse, conf_cache, retour_cache, derniere = r["session"]
    assert tuiles == ["—"] * 4 and bandeau and adresse == "" and conf_cache and retour_cache and "session requise" in derniere
    texte, etat, derniere, imgs, refus, ferme, sources = r["panne"]
    assert "source en panne" in texte and "Rien n'est déduit" in texte and etat == "—"
    assert "échec · HTTP 502" in derniere and XSS in derniere and imgs == 0
    assert refus.startswith("Refusé (HTTP 400)") and "hors du réseau" in refus and ferme
    assert "État du routeur · en panne" in sources and "Dernier résultat · lue" in sources
    assert [c[1] for c in appels if c[0] == "POST"] == ["api/v1/netmodes/routeur/apercu"]
    assert erreurs == []


def test_sans_session_sous_file_aucune_erreur():
    """fetch() refusé sous file:// : c'est le cas « sans session » du profil Aurora (§ 11.3)."""
    def scenario(nav):
        ctx = nav.new_context(viewport={"width": 420, "height": 900})
        pg = ctx.new_page()
        erreurs = []
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        pg.goto("file://" + str(PAGE))
        pg.wait_for_function("document.getElementById('pastille').textContent !== 'LECTURE…'")
        r = (pg.inner_text("#pastille"), pg.inner_text("#tEtat"), _sans_debordement(pg))
        ctx.close()
        return r, erreurs
    (pastille, etat, ok), erreurs = _avec_navigateur(scenario)
    assert pastille == "ÉTAT DU ROUTEUR ILLISIBLE" and etat == "—" and ok and erreurs == []


# ── Relecture de la tâche 7 : le bouton Confirmer dans la fenêtre de 180 s (Review Focus 3) ─────────────────────────────────────
def test_garde_du_dernier_releve_et_generation_dans_le_code():
    code = _code(SRC)
    assert "if (E.ok) { B = E; releveB = Date.now(); }" in code                     # dernier état lu avec succès gardé
    assert "if (g !== generation) { return; }" in code                               # lecture partie avant une écriture : jetée
    assert "suite = lecture.then(" in code                                           # relecture enchaînée, jamais abandonnée
    for verbe in ("appliquer", "confirmer", "retour"):
        assert 'ecrireEtat("%s"' % verbe in code, verbe
    assert "RELEVÉ ANCIEN" in code and "avant le retour automatique ; réessayez." in code and "échéance dépassée" in code


def _attendre(pg, condition, delai=6.0):
    fin = time.time() + delai
    while not condition():
        if time.time() > fin:
            raise AssertionError("condition non atteinte")
        pg.wait_for_timeout(50)


def test_une_lecture_ratee_garde_confirmer_et_relit_a_3_s():
    """À confirmer, puis l'état devient illisible (502) : Confirmer reste là, la page dit « relevé ancien » et relit à 3 s."""
    ech = _iso(time.time() + 100)
    lus = []

    def etat(_m, _c):
        lus.append(time.time())
        if len(lus) == 1:
            return 200, _etat(etat="en_attente", depuis=_iso(time.time() - 10), minuteur_actif=True, echeance=ech)
        return 502, {"detail": "contrôleur réseau injoignable"}
    api = {"netmodes/routeur/etat": etat, "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER · RELEVÉ ANCIEN", 6000)          # 2e lecture, ratée
        r = {"confirmer": pg.is_visible("#btnConfirmer"), "retour": pg.is_visible("#btnRetour"), "ancien": pg.inner_text("#ancien"),
             "compte": pg.inner_text("#phaseCompte"), "titre": pg.inner_text("#phaseTitre"), "tuile": pg.inner_text("#tEtatS"),
             "sources": pg.inner_text("#sources")}
        _attendre(pg, lambda: len(lus) >= 3)                                           # la lecture suivante, au rythme rapide
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["confirmer"] and r["retour"] and r["titre"] == "À confirmer"
    assert "Relevé ancien de" in r["ancien"] and "contrôleur réseau injoignable" in r["ancien"] and "3 s" in r["ancien"]
    assert re.fullmatch(r"1 min ([0-3]\d|40) s", r["compte"]), r["compte"]               # l'échéance du dernier relevé, toujours comptée
    assert r["tuile"].startswith("relevé ancien") and "État du routeur · en panne" in r["sources"]
    assert 2.5 <= lus[1] - lus[0] <= 4.5 and 2.5 <= lus[2] - lus[1] <= 4.5, [b - a for a, b in zip(lus, lus[1:])]
    assert j["erreurs"] == [] and not any(c[0] == "POST" for c in j["appels"])


def test_lecture_partie_avant_confirmer_jetee_et_relecture_enchainee():
    """Une lecture d'état en vol pendant Confirmer revient APRÈS lui avec l'ancien « en_attente » : elle est jetée, Confirmer
    ne réapparaît pas, et la relecture qui suit l'écriture part dès la fin de la lecture en vol (pas au tic suivant)."""
    ech = time.time() + 120
    box = {"phase": "attente", "garder": 0, "posts": 0}
    attente = _etat(etat="en_attente", minuteur_actif=True, echeance=_iso(ech))

    def etat(_m, _c):
        if box["garder"]:
            box["garder"] -= 1
            return None                                            # réponse retardée, donnée par le scénario
        return 200, (attente if box["phase"] == "attente" else _etat(etat="actif"))

    def confirmer(_m, _c):
        box["posts"] += 1
        box["phase"] = "actif"
        return 200, _etat(etat="actif")
    api = {"netmodes/routeur/etat": etat, "netmodes/routeur/derniere": (200, VIDE), "netmodes/routeur/confirmer": confirmer}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        box["garder"] = 1
        _attendre(pg, lambda: len(j["gardees"]) == 1)                                # une lecture en vol (tic à 3 s)
        pg.click("#btnConfirmer")
        _pastille(pg, "MODE ROUTEUR ACTIF", 3000)                                    # la réponse de Confirmer, tout de suite
        r = {"apres_post": pg.is_hidden("#btnConfirmer")}
        box["garder"] = 1                                                              # retient aussi la relecture enchaînée
        lache = time.time()
        j["gardees"][0].fulfill(status=200, content_type="application/json", body=json.dumps(attente))   # l'ancien état, en retard
        _attendre(pg, lambda: len(j["gardees"]) == 2, 2.0)
        suivante = [c[3] for c in j["appels"] if c[1].endswith("/etat")][-1]
        pg.wait_for_timeout(300)
        r["pendant"] = (pg.inner_text("#pastille"), pg.is_hidden("#btnConfirmer"))  # l'ancien état n'a pas été rendu
        j["gardees"][1].fulfill(status=200, content_type="application/json", body=json.dumps(_etat(etat="actif")))
        pg.wait_for_timeout(300)
        r["fin"] = (pg.inner_text("#pastille"), pg.is_hidden("#btnConfirmer"), pg.inner_text("#resultatBascule"))
        r["delai_relecture"] = suivante - lache
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["apres_post"]
    assert r["pendant"] == ("MODE ROUTEUR ACTIF", True), r["pendant"]               # jamais « à confirmer » de retour
    assert r["delai_relecture"] < 1.0, r["delai_relecture"]                          # enchaînée, pas le tic de 3 s
    pastille, cache, resultat = r["fin"]
    assert pastille == "MODE ROUTEUR ACTIF" and cache and "confirmé" in resultat
    assert box["posts"] == 1 and j["erreurs"] == [] and j["natifs"] == []


def test_confirmer_en_echec_dit_le_temps_restant_ou_l_echeance_depassee():
    def scenario(nav):
        r = []
        for ech, refus in ((time.time() + 100, "une application est déjà en cours"),
                           (time.time() - 5, "rien à confirmer : le mode routeur n'est pas en attente")):
            api = {"netmodes/routeur/etat": (200, _etat(etat="en_attente", minuteur_actif=True, echeance=_iso(ech))),
                   "netmodes/routeur/derniere": (200, VIDE), "netmodes/routeur/confirmer": (409, {"detail": refus})}
            ctx, pg, j = _page(nav, api)
            pg.goto("http://t.test/netmodes/routeur.html")
            _pastille(pg, "MODE ROUTEUR À CONFIRMER")
            pg.click("#btnConfirmer")
            pg.wait_for_selector("#resultatBascule:not([hidden])")
            r.append((pg.inner_text("#resultatBascule"), j["erreurs"]))
            ctx.close()
        return r
    (reste, e1), (depasse, e2) = _avec_navigateur(scenario)
    assert reste.startswith("Refusé (HTTP 409) : une application est déjà en cours — ")
    assert re.search(r"il reste 1 min ([0-3]\d|40) s avant le retour automatique ; réessayez\.$", reste), reste
    assert "rien à confirmer" in depasse and "échéance dépassée" in depasse and "il reste" not in depasse
    assert e1 == [] and e2 == []


# ── Arbitrage : cadence rapide BORNÉE (un relevé administrateur = un sudo root) ──────────────────────────────────────────────────
def test_cadence_rapide_bornee_dans_le_code():
    code = _code(SRC)
    assert "BORNE_RAPIDE = 300000" in code and "GRACE_ECHEANCE = 15000" in code
    assert "return r > -GRACE_ECHEANCE ? RAPIDE : LENT;" in code
    assert "if (depuisIllisible != null) { return t - depuisIllisible < BORNE_RAPIDE ? RAPIDE : LENT; }" in code


def _horloge(nav, api, base):
    """Page sous horloge simulée (page.clock), `base` en ms : le temps de la page avance seul jusqu'à pause_at, puis
    seulement sur ordre (run_for, fast_forward) ; le réseau reste réel."""
    ctx, pg, j = _page(nav, api)
    pg.clock.install(time=base / 1000)                      # en secondes (API Python), comme pause_at
    return ctx, pg, j


def _lus(j):
    return sum(1 for c in j["appels"] if c[1].endswith("/etat"))


def _rythme(pg, j, ms):
    """Lectures d'état déclenchées en avançant l'horloge de la page de `ms` (la lecture se termine en temps réel)."""
    avant = _lus(j)
    pg.clock.run_for(ms)
    pg.wait_for_timeout(400)
    return _lus(j) - avant


def _saut(pg, ms):
    """Saut dans le temps de la page : la minuterie en attente part une fois, la suivante est planifiée après la lecture."""
    pg.clock.fast_forward(ms)
    pg.wait_for_timeout(400)


def test_a_confirmer_rapide_jusqu_a_l_echeance_plus_15_s_puis_normal():
    base = (int(time.time()) + 1) * 1000
    api = {"netmodes/routeur/etat": (200, _etat(etat="en_attente", minuteur_actif=True, echeance=_iso(base / 1000 + 60))),
           "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _horloge(nav, api, base)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        pg.clock.pause_at((base + 10000) / 1000)
        pg.wait_for_timeout(400)
        r = {"avant": [_rythme(pg, j, 3100), _rythme(pg, j, 3100)]}                    # ~16 s : échéance à 60 s
        _saut(pg, 46000)                                                                 # ~62 s : échéance passée de 2 s
        r["grace"] = _rythme(pg, j, 3100)                                                # encore 3 s (retour à observer)
        r["confirmer"] = pg.is_visible("#btnConfirmer")
        _saut(pg, 20000)                                                                 # ~85 s : au-delà de échéance + 15 s
        r["apres"] = [_rythme(pg, j, 3100), _rythme(pg, j, 27500)]                      # rien à 3 s, une lecture à 30 s
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["avant"] == [1, 1] and r["grace"] == 1, r
    assert r["apres"] == [0, 1], r
    assert r["confirmer"] and j["erreurs"] == []


def test_echeance_inconnue_rapide_5_minutes_puis_lent():
    base = (int(time.time()) + 1) * 1000
    api = {"netmodes/routeur/etat": (200, _etat(etat="en_attente", minuteur_actif=False, echeance=None)),
           "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _horloge(nav, api, base)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        pg.clock.pause_at((base + 10000) / 1000)
        pg.wait_for_timeout(400)
        r = {"debut": _rythme(pg, j, 3100)}                                              # ~13 s depuis le début
        _saut(pg, 240000)                                                                # ~253 s : moins de 5 min
        r["avant_borne"] = _rythme(pg, j, 3100)
        r["compte"] = pg.inner_text("#phaseCompte")
        _saut(pg, 60000)                                                                 # ~316 s : plus de 5 min
        r["apres"] = [_rythme(pg, j, 3100), _rythme(pg, j, 27500)]
        r["confirmer"] = pg.is_visible("#btnConfirmer")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["debut"] == 1 and r["avant_borne"] == 1 and r["apres"] == [0, 1], r
    assert r["compte"] == "échéance inconnue" and r["confirmer"] and j["erreurs"] == []


def test_etat_illisible_rapide_5_minutes_puis_lent_et_confirmer_jusqu_a_l_echeance():
    base = (int(time.time()) + 1) * 1000
    lus = []

    def etat(_m, _c):
        lus.append(1)
        if len(lus) == 1:
            return 200, _etat(etat="en_attente", minuteur_actif=True, echeance=_iso(base / 1000 + 100))
        return 502, {"detail": "contrôleur réseau injoignable"}
    api = {"netmodes/routeur/etat": etat, "netmodes/routeur/derniere": (200, VIDE)}

    def scenario(nav):
        ctx, pg, j = _horloge(nav, api, base)
        pg.goto("http://t.test/netmodes/routeur.html")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER")
        _pastille(pg, "MODE ROUTEUR À CONFIRMER · RELEVÉ ANCIEN", 8000)                # illisible depuis ~3 s
        pg.clock.pause_at((base + 10000) / 1000)
        pg.wait_for_timeout(400)
        r = {"debut": _rythme(pg, j, 3100), "confirmer_avant": pg.is_visible("#btnConfirmer")}
        _saut(pg, 100000)                                                                # ~113 s : échéance (100 s) passée
        r["echu"] = (_rythme(pg, j, 3100), pg.is_hidden("#btnConfirmer"))               # encore 3 s ; relevé ancien échu
        _saut(pg, 200000)                                                                # ~316 s : illisible depuis > 5 min
        r["apres"] = [_rythme(pg, j, 3100), _rythme(pg, j, 27500)]
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["debut"] == 1 and r["confirmer_avant"], r
    assert r["echu"] == (1, True), r
    assert r["apres"] == [0, 1], r
    assert j["erreurs"] == []

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3963 — GET /situations : assemblage sans balayage, sources muettes dites, décisions en attente, phrases accordées."""
import copy
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense, defense_etat, main, situations as S  # noqa: E402
from secubox_core.auth import require_lecture  # noqa: E402

T = 1_764_000_000.0
IP = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def pop(**k):
    return dict({"id": "famille:collecte", "famille": "collecte", "nom_cible": "depot.exemple.test", "adresses": 2454, "reseaux": 58, "une": 71, "le3": 96,
                 "classes": {"proxy_loue": 84, "hebergeur": 16, "inventee": 3}, "serie": [10, 20, 30, 40, 50, 600, 12], "bans": 40, "actives_24h": 212,
                 "bannies_24h": 1, "rotation": True, "etat": "observee", "premier": int(T) - 500000, "dernier": int(T) - 60}, **k)


def sites(**k):
    return dict({"disponible": True, "genere_le": int(T), "perime": False, "journal": "ok", "heures_mesurees": 24,
                 "chiffres": {"ecartees": 11480, "passees": 312, "series": {"ecartees": [1] * 24, "passees": [0] * 24}}, "sites": [],
                 "decisions": {"rotation": {"etat": "ok", "mode": "auto", "campagnes": []}, "campagnes": {"etat": "absent"}, "acteurs": {"etat": "absent"}}}, **k)


DOSSIER = {"disponible": True, "id": "depot.exemple.test", "titre": "depot.exemple.test", "sous_titre": "200 requêtes hostiles", "attaque": True, "total": 200,
           "etiquettes": [["à décider", "r"], ["sous attaque", "r"]], "phrase": "200 requêtes hostiles en 24 h.", "serie": [None] * 23 + [200], "debut": 1, "pas": 3600, "partielles": [],
           "couches": [{"cle": "arrete", "nom": "Arrêté", "serie": [None] * 23 + [200]}], "chaine": [], "categories": [], "origine": {"unite": "requêtes", "lignes": []},
           "faits": [{"ts": int(T), "texte": "Pic depuis 203.0.113.9 et 2001:db8::1:2:3", "preuve": "journal"}], "geste": {"href": "/waf/#modes"}}


class Banc:
    def __init__(self, tmp, monkeypatch):
        self.rep, self.appels, self.tmp, self.mp = {}, [], tmp, monkeypatch
        self.rep = {("waf", "/dossiers/sites"): sites(), ("waf", "/populations"): {"disponible": True, "age_s": 60, "populations": []},
                    ("actord", "/proposals"): {"genere_le": int(T), "propositions": []}}
        self.sante({"haproxy": {"ok": True}})
        self.lents({})

    def lire(self, source, chemin, entetes=None, delai=3.0):
        self.appels.append((source, chemin, dict(entetes or {})))
        r = self.rep.get((source, chemin))
        if isinstance(r, str):
            return {"ok": False, "donnees": None, "erreur": r}
        return {"ok": True, "donnees": copy.deepcopy(r), "erreur": None} if r is not None else {"ok": False, "donnees": None, "erreur": "socket absent"}

    def _ts(self, recul):
        return datetime.fromtimestamp(T - recul, tz=timezone.utc).isoformat()

    def sante(self, checks, recul=30):
        (self.tmp / "sante.json").write_text(json.dumps({"generated_at": self._ts(recul), "checks": checks}))

    def lents(self, vhosts, recul=30):
        (self.tmp / "sites.json").write_text(json.dumps({"timestamp": self._ts(recul), "vhosts": vhosts}))

    def calc(self):
        return S.calculer({}, T)


@pytest.fixture
def banc(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_SOC_SANTE", str(tmp_path / "sante.json"))
    monkeypatch.setenv("SECUBOX_SOC_SANTE_SITES", str(tmp_path / "sites.json"))
    b = Banc(tmp_path, monkeypatch)
    monkeypatch.setattr(S.substrat, "lire", b.lire)
    S.vider()
    yield b
    S.vider()


def src(p, i):
    return next(x for x in p["sources"] if x["id"] == i)


def test_rien_a_signaler_seulement_si_toutes_les_sources_parlent(banc):
    p = banc.calc()
    assert p["situations"] == [] and p["complet"] and p["chiffres"]["a_decider"] == 0 and p["chiffres"]["en_cours"] == 0
    assert p["chiffres"]["ecartees_24h"] == 11480 and p["chiffres"]["passees_24h"] == 312
    banc.rep.clear()
    p = banc.calc()
    assert not p["complet"] and src(p, "waf_sites")["erreur"] == "injoignable" and src(p, "sade")["erreur"] == "injoignable"
    assert p["chiffres"]["a_decider"] is None and p["chiffres"]["en_cours"] is None and p["chiffres"]["ecartees_24h"] is None


@pytest.mark.parametrize("erreur,motif", [("http 404", "mesure absente de cette version"), ("http 401", "lecture refusée"), ("délai", "ne répond pas à temps"),
                                          ("socket absent", "injoignable"), ("http 500", "injoignable")])
def test_waf_plus_ancien_ou_muet_est_dit_et_le_reste_tient(banc, erreur, motif):
    banc.rep[("waf", "/dossiers/sites")] = erreur
    banc.rep[("waf", "/populations")]["populations"] = [pop()]
    p = banc.calc()
    assert src(p, "waf_sites")["erreur"] == motif and src(p, "waf_populations")["ok"]
    assert [x["titre"] for x in p["situations"]] == ["Collecte : depot.exemple.test"]
    assert p["chiffres"]["en_cours"] == 1 and p["chiffres"]["en_cours_partiel"] and p["chiffres"]["a_decider"] is None


def test_releves_figes_ou_absents_sont_dits(banc):
    banc.rep[("waf", "/dossiers/sites")] = sites(perime=True)
    banc.rep[("waf", "/populations")] = {"disponible": False}
    p = banc.calc()
    assert src(p, "waf_sites")["erreur"] == "relevé figé" and src(p, "waf_populations")["erreur"] == "aucun relevé"
    banc.rep[("waf", "/dossiers/sites")] = {"disponible": False}
    banc.rep[("waf", "/populations")] = {"disponible": True, "age_s": 90000, "populations": []}
    p = banc.calc()
    assert src(p, "waf_sites")["erreur"] == "premier relevé en cours" and src(p, "waf_populations")["erreur"] == "relevé figé"


def test_population_phrase_serie_par_jour_jamais_par_heure(banc):
    banc.rep[("waf", "/populations")]["populations"] = [pop(), pop(id="famille:autre", etat="inactive"), pop(id="x", actives_24h=0), "x", {"id": 3}, pop(id="<b>")]
    p = banc.calc()
    x, = p["situations"]
    assert x["phrase"] == ("Recopie du contenu sur depot.exemple.test depuis 2 454 adresses de 58 réseaux en sept jours. 71 % des adresses n’ont été vues "
                           "qu’une fois. 212 sont actives depuis 24 h, 1 est bannie. Hier : 600 tentatives, contre 30 par jour en moyenne les jours d’avant.")
    assert x["serie"] is None and x["couches"] is None and x["serie_jours"] == [10, 20, 30, 40, 50, 600, 12] and "par jour" in x["serie_note"]
    assert [c["n"] for c in x["chaine"]] == [2454, 212, 1] and [o["nom"] for o in x["origine"]["lignes"]] == ["Relais loués", "Hébergeurs"]
    assert x["geste"]["href"] == "/waf/#campaigns"


def test_accords_au_singulier(banc):
    banc.rep[("waf", "/populations")]["populations"] = [pop(adresses=1, reseaux=1, actives_24h=1, bannies_24h=1, etat="bannie", rotation=False, serie=[0] * 7)]
    x, = banc.calc()["situations"]
    assert "depuis 1 adresse de 1 réseau" in x["phrase"] and "La seule active depuis 24 h est bannie." in x["phrase"]
    assert x["sous_titre"] == "1 adresse active en 24 h" and x["urgence"] == 35 and "0 tentative," in x["phrase"]


def test_rotation_proposee_fusionnee_avec_sa_population_sinon_seule(banc):
    c = {"id": "rotation:0a1b2c3d", "hote": "depot.exemple.test", "etablie_le": int(T) - 900, "dernier": int(T) - 5, "sources": 640, "a_bannir": 19, "bannies": 0, "epargnees": 3}
    banc.rep[("waf", "/dossiers/sites")] = sites(decisions={"rotation": {"etat": "ok", "mode": "propose", "campagnes": [c, dict(c, id="rotation:ffffffff", a_bannir=1)]}})
    banc.rep[("waf", "/populations")]["populations"] = [pop(id="rotation:0a1b2c3d")]
    p = banc.calc()
    assert [x["id"] for x in p["situations"]] == ["population:rotation:0a1b2c3d", "rotation:rotation:ffffffff"] and p["chiffres"]["a_decider"] == 2
    assert "19 adresses sont proposées au bannissement et attendent ta décision." in p["situations"][0]["phrase"]
    assert "1 est proposée au bannissement et attend ta décision." in p["situations"][1]["phrase"]
    assert all(x["geste"]["href"] == "/actor/" for x in p["situations"])
    for k in ({"mode": "auto"}, {"etat": "perime"}):
        banc.rep[("waf", "/dossiers/sites")]["decisions"]["rotation"].update({"mode": "propose", "etat": "ok", **k})
        assert banc.calc()["chiffres"]["a_decider"] == 0


def test_candidats_des_bans_automatiques(banc):
    d = {"rotation": {}, "campagnes": {"etat": "ok", "mode": "propose", "a_bannir": 3, "bannis": 1, "genere_le": int(T)}, "acteurs": {"etat": "perime", "mode": "propose", "a_bannir": 9}}
    banc.rep[("waf", "/dossiers/sites")] = sites(decisions=d)
    x, = banc.calc()["situations"]
    assert x["id"] == "candidats:campagnes" and "3 adresses sont proposées" in x["phrase"] and x["poids"] == 3


def test_site_sous_attaque_detail_lu_et_sans_adresse(banc):
    banc.rep[("waf", "/dossiers/sites")] = sites(sites=[{"id": f"s{i}.exemple.test", "titre": "s", "attaque": i < 9, "etiquettes": []} for i in range(12)] + [
        {"id": "noms-inconnus", "attaque": True}, {"id": "../x", "attaque": True}])
    for i in range(12):
        banc.rep[("waf", f"/dossiers/sites/s{i}.exemple.test")] = dict(DOSSIER, id=f"s{i}.exemple.test")
    p = banc.calc()
    assert len(p["situations"]) == S.SITES_MAX and len([a for a in banc.appels if a[1].startswith("/dossiers/sites/")]) == S.SITES_MAX
    x = p["situations"][0]
    assert x["couches"][0]["cle"] == "arrete" and x["geste"]["href"].startswith("/waf/#sites:s") and x["etiquettes"] == [["sous attaque", "r"]]
    assert not IP.search(json.dumps(p)) and "2001:db8" not in json.dumps(p) and p["chiffres"]["a_decider"] == 0


def test_detail_muet_n_est_attendu_qu_une_fois(banc):
    banc.rep[("waf", "/dossiers/sites")] = sites(sites=[{"id": f"s{i}.exemple.test", "titre": f"s{i}", "attaque": True, "etiquettes": [["sous attaque", "r"]], "total": 5} for i in range(4)])
    p = banc.calc()
    assert len([a for a in banc.appels if a[1].startswith("/dossiers/sites/")]) == 1
    assert len(p["situations"]) == 4 and all("n’a pas pu être lu" in x["phrase"] and x["couches"] is None for x in p["situations"])


def _props(*modes):
    return {"genere_le": int(T), "propositions": [{"actor": f"ACT-{i:04d}", "mode": m, "ips": [f"203.0.113.{i}"], "priorite": 60 + i, "ttl_s": 3600, "raison": "203.0.113.9"} for i, m in enumerate(modes, 1)]}


def test_sade_attend_une_decision_seulement_si_le_mode_la_demande(banc, monkeypatch):
    banc.rep[("actord", "/proposals")] = _props("ban", "ban", "limiter", "observe")
    monkeypatch.setattr(defense_etat, "mode_courant", lambda: "observe")
    x, = banc.calc()["situations"]
    assert x["etiquettes"] == [["observation", ""]] and "rien ne t’est demandé" in x["phrase"]
    monkeypatch.setattr(defense_etat, "mode_courant", lambda: "reactive")
    p = banc.calc()
    x, = p["situations"]
    assert x["phrase"].startswith("SADE propose 3 gestes : 2 bannissements, 1 ralentissement.") and "Ils attendent ta décision." in x["phrase"]
    assert p["chiffres"]["a_decider"] == 1 and x["geste"]["href"] == "/soc/#tdef" and not IP.search(json.dumps(p))
    emp = [q["empreinte"] for q in defense._propositions({"ok": True, "donnees": banc.rep[("actord", "/proposals")]})]
    monkeypatch.setattr(defense_etat, "etats_decisions", lambda: {e: "refuse" for e in emp})
    assert banc.calc()["situations"] == []

    def casse():
        raise defense_etat.EtatIndisponible("x")
    monkeypatch.setattr(defense_etat, "etats_decisions", casse)
    p = banc.calc()
    assert src(p, "sade")["erreur"] == "base des décisions illisible" and p["chiffres"]["a_decider"] is None


def test_services_seulement_si_une_mesure_fraiche_le_dit(banc):
    banc.sante({"nginx": {"ok": False, "details": {"ip": "203.0.113.1"}}, "comptes-admin": {"ok": False, "niveau": "avertissement"}, "<b>": {"ok": False}, "x": "y"})
    banc.lents({"a.exemple.test": {"status": "slow", "latency_ms": 1840.4}, "b.exemple.test": {"status": "down", "status_code": 404},
                "c.exemple.test": {"status": "down", "error": "timeout"}, "d.exemple.test": {"status": "down", "status_code": 502}, "<i>": {"status": "down", "error": "timeout"}})
    p = banc.calc()
    assert [x["id"] for x in p["situations"]] == ["vital:nginx", "sites-muets", "sites-lents"]
    assert "2 sites ne répondent pas ou rendent une erreur au dernier contrôle : c.exemple.test, d.exemple.test." in p["situations"][1]["phrase"]
    assert "à 1 840 ms" in p["situations"][2]["phrase"] and not IP.search(json.dumps(p))
    banc.sante({"nginx": {"ok": False}}, recul=4000)
    banc.lents({"a.exemple.test": {"status": "slow", "latency_ms": 9e3}}, recul=4000)
    p = banc.calc()
    assert p["situations"] == [] and src(p, "sante")["erreur"] == "mesure périmée" and src(p, "sante_sites")["erreur"] == "mesure périmée"


@pytest.mark.parametrize("brut", [None, "{", "[]", "lien"])
def test_mesure_de_sante_absente_ou_illisible_est_dite(banc, brut):
    f = banc.tmp / "sante.json"
    f.unlink()
    if brut == "lien":
        (banc.tmp / "cible.json").write_text("{}")
        f.symlink_to(banc.tmp / "cible.json")
    elif brut:
        f.write_text(brut)
    p = banc.calc()
    assert src(p, "sante")["erreur"] == ("aucune mesure" if brut is None else "illisible") and p["situations"] == []


def test_tri_par_urgence_et_plafond_des_populations(banc):
    banc.rep[("waf", "/populations")]["populations"] = [pop(id=f"p{i}", etat="bannie" if i % 2 else "observee", actives_24h=i + 1) for i in range(30)]
    banc.sante({"nginx": {"ok": False}})
    p = banc.calc()
    u = [x["urgence"] for x in p["situations"]]
    assert u == sorted(u, reverse=True) and u[0] == 85 and len(u) == S.POPULATIONS_MAX + 1 and p["autres_populations"] == 18


def test_route_gardee_cache_court_et_identifiants_retransmis(banc):
    c = TestClient(main.app)
    assert c.get("/situations", headers={"X-SecuBox-LAN": "0"}).status_code == 401
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    try:
        banc.rep[("waf", "/populations")]["populations"] = [pop()]
        j = c.get("/situations", headers={"Authorization": "Bearer a"}).json()
        n = len(banc.appels)
        assert j["age_s"] >= 0 and len(j["situations"]) == 1
        assert c.get("/situations", headers={"Authorization": "Bearer a"}).json()["genere_le"] == j["genere_le"] and len(banc.appels) == n
        c.get("/situations", headers={"Authorization": "Bearer b"})
        assert len(banc.appels) == 2 * n                                  # un cache par appelant
        assert banc.appels[0][2]["Authorization"] == "Bearer a" and all("Authorization" not in e for s, _, e in banc.appels if s == "actord")
    finally:
        main.app.dependency_overrides.pop(require_lecture, None)


def test_aucun_journal_balaye():
    code = Path(S.__file__).read_text(encoding="utf-8")
    assert ".log" not in code and "subprocess" not in code and "glob" not in code.split('"""', 2)[2]


# ── page ───────────────────────────────────────────────────────────────────────────────────────────────────────────

WWW = Path(__file__).resolve().parents[1] / "www" / "soc"
PAGE = (WWW / "situations.html").read_text(encoding="utf-8")
XSS = "<img src=x onerror=window.xss=1>"
NOW = int(time.time())


def test_page_statique():
    assert len(re.findall(r"<script", PAGE)) == 1 and "<link" not in PAGE and "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in PAGE
    for interdit in ("innerHTML", "insertAdjacentHTML", "document.write", "eval(", "confirm(", "alert(", "prompt(", "POST", "scrollHeight", "100vh", "lorem"):
        assert interdit not in PAGE, interdit
    assert "'/api/v1/soc/situations'" in PAGE and "onglet:'situations'" in PAGE


@pytest.fixture(scope="module")
def nav():
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def reponse(**k):
    def sit(i, **kk):
        return dict({"id": f"x{i}", "titre": f"Situation {i} {XSS}", "sous_titre": XSS, "etiquettes": [["à décider", "r"], [XSS, "o"]], "urgence": 90 - i, "phrase": XSS,
                     "serie": None, "serie_jours": [1, 2, 3, None, 5, 6, 0], "serie_note": "Mesuré par jour.", "couches": None, "chaine": [{"nom": XSS, "n": None, "cle": "__proto__"}],
                     "categories": [], "origine": {"unite": "%", "lignes": [{"nom": XSS, "n": 40}]}, "faits": [{"ts": NOW, "texte": XSS, "preuve": XSS}],
                     "geste": {"libelle": "Ouvrir", "href": "/waf/#campaigns", "note": XSS, "genre": ""}}, **kk)
    return dict({"genere_le": NOW, "age_s": 2, "situations": [sit(0), sit(1, serie_jours=None, serie_note=None), sit(2)], "autres_populations": 2,
                 "sources": [{"id": "a", "nom": "WAF, campagnes", "ok": True, "erreur": None}, {"id": "b", "nom": XSS, "ok": False, "erreur": "injoignable"}],
                 "chiffres": {"a_decider": 3, "a_decider_partiel": False, "en_cours": 3, "en_cours_partiel": True, "ecartees_24h": 11480, "passees_24h": None,
                              "heures_mesurees": 5, "series": {"ecartees": [None] * 19 + [1, 2, 3, 4, 5], "passees": None}}}, **k)


def ouvre(nav, rep, taille=(1280, 900), url="situations.html?embed=1", reduit=False):
    ctx = nav.new_context(viewport={"width": taille[0], "height": taille[1]}, reduced_motion="reduce" if reduit else "no-preference", locale="fr-FR", timezone_id="Europe/Paris")
    p = ctx.new_page()
    p.erreurs, p.appels = [], []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("#")[0]
        if u.startswith("/api/"):
            p.appels.append(r.request.method + " " + u)
            c = rep if u == "/api/v1/soc/situations" else 404
            return r.fulfill(status=c if isinstance(c, int) else 200, content_type="application/json", body="{}" if isinstance(c, int) else json.dumps(c))
        f = WWW / (u.split("?")[0][len("/soc/"):] or "index.html") if u.startswith("/soc/") else None
        if f is not None and f.is_file():
            return r.fulfill(status=200, content_type="text/html" if f.suffix == ".html" else "text/javascript", body=f.read_text(encoding="utf-8"))
        return r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/soc/" + url)
    return p


def test_page_situations_donnees_hostiles_inertes_et_sources_dites(nav):
    p = ouvre(nav, reponse())
    p.wait_for_selector("#dossier h2")
    t = p.inner_text("body").replace(" ", " ")
    assert p.evaluate("window.xss") is None and p.locator("img").count() == 0 and XSS in t
    assert f"Source « {XSS} » : injoignable." in t and "au moins : 1 source lue sur 2" in t and "5 heures mesurées" in t and "Et 2 autres campagnes actives" in t
    assert "Sept derniers jours" in t and "1 jour non mesuré" in p.get_attribute(".graphe", "aria-label").replace(" ", " ") and "Mesuré par jour." in t
    assert p.locator("#chiffres b").all_inner_texts()[3] == "—" and p.locator("#chiffres svg").count() == 1
    p.click("#liste .item >> nth=1")
    p.wait_for_function("document.querySelector('#dossier').textContent.includes('— pas mesuré')")
    p.focus("#liste .item >> nth=1")
    p.keyboard.press("ArrowDown")
    p.keyboard.press("Enter")
    p.wait_for_function("document.querySelector('#dossier h2').textContent.startsWith('Situation 2')")
    assert p.erreurs == [] and set(p.appels) == {"GET /api/v1/soc/situations"}
    p.context.close()


def test_page_aucune_situation_jamais_confondue_avec_une_source_muette(nav):
    p = ouvre(nav, reponse(situations=[]))
    p.wait_for_function("document.querySelector('#liste').textContent.includes('Aucune situation visible, mais une source ne répond pas.')")
    p.context.close()
    p = ouvre(nav, reponse(situations=[], sources=[{"nom": "a", "ok": True}]))
    p.wait_for_function("document.querySelector('#liste').textContent.includes('Aucune situation en cours.')")
    p.context.close()


@pytest.mark.parametrize("statut,attendu,session", [(401, "session requise", True), (404, "ne sert pas encore les situations", False), (502, "SOC injoignable", False)])
def test_page_refus_dit(nav, statut, attendu, session):
    p = ouvre(nav, statut)
    p.wait_for_function("document.querySelector('#liste .vide')&&!document.querySelector('#liste .vide').textContent.startsWith('Chargement')")
    assert attendu in p.inner_text("#liste") and p.locator("#session").is_visible() is session and p.locator("#chiffres b").all_inner_texts() == ["—"] * 4
    p.context.close()


@pytest.mark.parametrize("largeur", [1280, 400])
def test_page_sans_debordement_et_mouvement_reduit(nav, largeur):
    p = ouvre(nav, reponse(), taille=(largeur, 800), reduit=True)
    p.wait_for_selector("#dossier h2")
    assert p.evaluate("document.documentElement.scrollWidth") <= largeur and p.evaluate("document.getAnimations().length") == 0
    assert p.evaluate("[...document.querySelectorAll('button,.bouton')].filter(e=>e.offsetParent&&e.getBoundingClientRect().height<40).length") == 0
    assert p.evaluate("Math.min(...[...document.querySelectorAll('.app *')].filter(e=>e.childNodes.length&&[...e.childNodes].some(n=>n.nodeType===3&&n.data.trim())&&e.tagName!=='TITLE').map(e=>parseFloat(getComputedStyle(e).fontSize)))") >= 13.6
    p.context.close()


def test_page_demonstration_annoncee_sans_appel(nav):
    p = ouvre(nav, reponse(), url="situations.html?demo=1")
    p.wait_for_selector("#dossier h2")
    assert p.locator("#demo").is_visible() and p.appels == [] and p.erreurs == []
    p.context.close()


def test_vigie_ouvre_situations_et_suit_le_fragment(nav):
    p = ouvre(nav, reponse(), url="?embed=1")
    f = p.frame_locator("#vueFrame")
    f.locator("#dossier h2").wait_for()
    assert not [x for x in p.frames if x.url.endswith("guardian.html")] or p.evaluate("document.getElementById('guardianFrame').loading") == "lazy"
    p.wait_for_function("parseInt(document.getElementById('vueFrame').style.height)!==1400")
    p.evaluate("location.hash='tdef'")
    p.wait_for_function("document.getElementById('tdef').getAttribute('aria-selected')==='true'")
    assert p.get_attribute("#vueFrame", "src") == "defense.html?embed=1"
    p.evaluate("location.hash='e1'")                                      # un autre identifiant n'ouvre rien
    p.wait_for_timeout(100)
    assert p.get_attribute("#tdef", "aria-selected") == "true"
    p.context.close()

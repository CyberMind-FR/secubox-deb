# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2706 — /ad-guard/ en direct : bande d'état, métriques rafraîchies seules, variations, démonstration, 420 px.

Statique + API (module `api/direct.py`, route `/statut-direct`) + vrai navigateur avec l'API simulée sur http://sbx.test (données factices).
Le temps du navigateur est celui de `page.clock` : on avance l'horloge, on ne dort pas.
"""
import json
import re
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
PAGE = ICI / "www" / "ad-guard" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
DIRECT = SRC[SRC.index("// ══ Direct (#2706)"):SRC.index("// ══ Aurora")]


# ── statique ────────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_page_autonome_et_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S)).replace("onerror=alert(1)", "")
    for natif in ("confirm(", "alert(", "prompt("):
        assert not re.search(r"(?<![A-Za-z.])" + re.escape(natif), code)
    assert "lorem" not in SRC.lower()


def test_bloc_direct_sans_innerhtml_ni_mesure_inventee():
    assert "innerHTML" not in DIRECT and "insertAdjacentHTML" not in DIRECT and "outerHTML" not in DIRECT
    assert "Math.random" not in DIRECT                              # la démonstration bouge avec un temps virtuel, pas avec du hasard
    assert "localStorage.getItem('sbx_token')" in DIRECT and "try" in DIRECT.split("localStorage.getItem('sbx_token')")[0][-80:]
    assert "method: 'POST'" not in DIRECT and "'POST'" not in DIRECT      # le direct est en lecture seule


def test_routes_lues_par_le_direct_et_anciennes_routes_intactes():
    for r in ("/statut-direct", "/adblock-tv/serie?heures=1&pas=60", "/adblock-tv/status", "/adblock-tv/flux?heures=1"):
        assert r in DIRECT
    for ancien in ("api('/stats')", "'/blocklist/top?limit=30'", "'/blocklist/update', 'POST'", "`/blocklist/add?domain=", "`/blocklist/${encodeURIComponent(domain)}`, 'DELETE'",
                   "'/delayed/process', 'POST'", "'/learn/run', 'POST'", "'/learn/thresholds', 'POST'", "'/adblock-tv/etat', 'POST'", "'/adblock-tv/mode', 'POST'",
                   "'/adblock-tv/clients', 'POST'", "'/adblock-tv/custom', 'POST'", "'/adblock-tv/sonde', 'POST'", "'/adblock-tv/auto/detection/reglage', 'POST'",
                   "'/adblock-tv/simple/suspects/legitime', 'POST'", "localStorage.getItem('sbx_token')"):
        assert ancien in SRC, ancien


def test_tuiles_avec_definition_et_mouvement_respectueux():
    assert len(re.findall(r'class="tuile" id="t-[a-z]+" title="[^"]{30,}"', SRC)) == 6
    assert len(re.findall(r'class="etat inc" id="e-[a-z]+" title="[^"]{30,}"', SRC)) == 5
    assert "prefers-reduced-motion" in SRC and "sbxVue" in SRC and "embed" in SRC and "demo" in SRC


# ── API : module direct ─────────────────────────────────────────────────────────────────────────────────────────────────
def _modules():
    import importlib
    return importlib.import_module("api.direct")


class _Rep:
    def __init__(self, sortie):
        self.stdout = sortie


class _Magasin:
    def __init__(self, now):
        self.now = now

    def recents(self, clients, depuis, limite):
        return [{"ts": self.now - 3}]

    def par_client(self):
        return [{"client": "a", "derniere_vue": self.now - 10}, {"client": "b", "derniere_vue": self.now - 4000}]


def test_etat_direct_lit_les_fichiers_et_systemd(tmp_path, monkeypatch):
    d = _modules()
    now = 1_791_900_000
    st = tmp_path / "sinkhole-status.json"
    st.write_text(json.dumps({"ok": True, "enabled": True, "blocked": 412800, "reloaded": True, "ts": now - 86400}))
    et = tmp_path / "dnssensor-etat.json"
    et.write_text(json.dumps({"emis": {"a|dns.dga|x.test": now - 100, "b|dns.dga|y.test": now - 3 * 86400}}))
    monkeypatch.setattr(d, "SINKHOLE_STATUS", st)
    monkeypatch.setattr(d, "ETAT_CAPTEUR", et)
    monkeypatch.setattr(d, "DROPIN_PUITS", tmp_path / "absent.conf")
    r = d.etat_direct(now, magasin=_Magasin(now), lancer=lambda argv, **kw: _Rep("active\n" if "unbound.service" in argv else "inactive\n"))
    assert r["maintenant"] == now
    assert r["resolveur"] == {"actif": True} and r["capteur"]["actif"] is False and r["flux"]["actif"] is False
    assert r["puits"]["actif"] is True and r["puits"]["ok"] is True and r["puits"]["recharge"] is True
    assert r["listes"] == {"domaines": 412800, "maj_ts": now - 86400, "peremption_s": 9 * 86400}
    assert r["capteur"]["constats_24h"] == 1 and r["capteur"]["dernier_constat_ts"] == now - 100
    assert r["flux"]["dernier_evenement_ts"] == now - 3
    assert r["clients"] == {"actifs_5min": 1, "vus": 2}


def test_ce_qui_est_illisible_reste_inconnu_jamais_un_zero(tmp_path, monkeypatch):
    d = _modules()
    monkeypatch.setattr(d, "SINKHOLE_STATUS", tmp_path / "nope.json")
    monkeypatch.setattr(d, "ETAT_CAPTEUR", tmp_path / "nope2.json")
    monkeypatch.setattr(d, "DROPIN_PUITS", tmp_path / "nope3.conf")

    def boum(argv, **kw):
        raise OSError("pas de systemctl")
    r = d.etat_direct(1_791_900_000, magasin=None, lancer=boum)
    assert r["resolveur"]["actif"] is None and r["capteur"]["actif"] is None and r["flux"]["actif"] is None
    assert r["puits"] == {"actif": None, "ok": None, "erreur": None, "recharge": None}
    assert r["listes"]["domaines"] is None and r["listes"]["maj_ts"] is None
    assert r["capteur"]["constats_24h"] is None and r["clients"] == {"actifs_5min": None, "vus": None}
    assert d.unite_active("x", lambda *a, **k: _Rep("activating\n")) is None


def test_synchronisation_en_echec_date_les_listes_sur_le_fichier_de_regles(tmp_path, monkeypatch):
    d = _modules()
    puits, listes = d.puits_et_listes({"ok": False, "enabled": True, "error": "unbound-checkconf a refusé", "ts": 5, "blocked": 10}, 1234)
    assert puits["ok"] is False and "refusé" in puits["erreur"] and listes["maj_ts"] == 1234 and listes["domaines"] == 10


def test_la_route_existe_en_lecture_seule():
    from api import main
    routes = [r for r in main.app.routes if getattr(r, "path", "") == "/statut-direct"]
    assert routes and routes[0].methods == {"GET"}


# ── navigateur ──────────────────────────────────────────────────────────────────────────────────────────────────────────
playwright = pytest.importorskip("playwright.sync_api")

NOW = 29_865_000 * 60 + 30            # 30 s après le début d'une minute
M0 = NOW // 60


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as e:                                   # navigateur absent de cette machine
            pytest.skip(str(e))
        yield b
        b.close()


def serie(cur=(100, 20), prev=(80, 10), reste=(50, 5)):
    pts = []
    for m in range(M0 - 59, M0):
        r, b = cur if m >= M0 - 5 else prev if m >= M0 - 10 else reste
        pts.append({"ts": m * 60, "requetes": r, "bloquees": b, "classees": 0})
    return {"pas_s": 60, "points": pts}


def etat(**sur):
    base = {"maintenant": NOW, "resolveur": {"actif": True}, "puits": {"actif": True, "ok": True, "erreur": None, "recharge": True},
            "listes": {"domaines": 412800, "maj_ts": NOW - 3 * 86400, "peremption_s": 9 * 86400}, "capteur": {"actif": True, "constats_24h": 2, "dernier_constat_ts": NOW - 600},
            "flux": {"actif": True, "dernier_evenement_ts": NOW - 4}, "clients": {"actifs_5min": 4, "vus": 9}}
    base.update(sur)
    return base


TV = {"actif": True, "clients": [{"ip": "192.0.2.21", "nom": "tv-salon", "mode": "auto"}], "erreur": None, "listes": {"domaines": 412800}}
FLUX = {"heures": 1, "domaines": [
    {"domaine": "pub.exemple.test", "categorie": "advertising", "requetes": 420, "bloquees": 400, "service": "Régie exemple"},
    {"domaine": "suivi.exemple.test", "categorie": "tracking", "requetes": 300, "bloquees": 200, "service": ""},
    {"domaine": "propre.exemple.test", "categorie": "", "requetes": 900, "bloquees": 0, "service": ""}], "services": []}


def api_nominale():
    return {"/statut-direct": (200, etat()), "/adblock-tv/serie": (200, serie()), "/adblock-tv/status": (200, TV), "/adblock-tv/flux": (200, FLUX)}


def ouvre(navigateur, routes, query="", taille=None, horloge=True, panne=None):
    """Ouvre la page avec l'API simulée. `routes` : chemin -> (statut, corps) ; `panne` : liste mutable, non vide = le réseau tombe."""
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    panne = panne if panne is not None else []

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ad-guard":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        brut = r.request.url.split("/api/v1/ad-guard", 1)[1]
        chemin = brut.split("?")[0]
        # les relevés du direct portent une étiquette : l'ancienne page appelle aussi /serie et /flux (autres périodes) et ses propres minuteries
        etiquette = "#direct" if brut in ("/adblock-tv/serie?heures=1&pas=60", "/adblock-tv/flux?heures=1") else ""
        appels.append((r.request.method, chemin + etiquette))
        if panne:
            r.abort()
            return
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/ad-guard/**", api)
    if horloge:
        p.clock.install(time=NOW * 1000)
    p.goto("http://sbx.test/ad-guard/" + query)
    return ctx, p, erreurs, appels


def nb(appels, chemin):
    return len([a for a in appels if a[1] == chemin and a[0] == "GET"])


def rel(appels):
    return len([a for a in appels if a[1] == "/statut-direct"])


def attend(p, n, chemin="/statut-direct", appels=None):
    p.wait_for_function("() => LIVE.tick >= %d && !LIVE.enCours" % n)


def avance(p, ms, tick):
    p.clock.run_for(ms)
    attend(p, tick)


def texte(p, sel):
    return p.inner_text(sel).strip()


def test_tout_vert_bande_et_tuiles(navigateur):
    ctx, p, err, appels = ouvre(navigateur, api_nominale())
    attend(p, 1)
    assert texte(p, "#e-resolveur .mot") == "Unbound actif" and "ok" in p.get_attribute("#e-resolveur", "class").split()
    assert texte(p, "#e-puits .mot") == "Puits actif" and "412" in texte(p, "#e-puits .det")
    assert texte(p, "#e-listes .mot") == "Listes à jour" and "3 j" in texte(p, "#e-listes .det")
    assert texte(p, "#e-capteur .mot") == "Capteur actif" and "2 constats" in texte(p, "#e-capteur .det")
    assert texte(p, "#e-moteur .mot") == "Moteur actif" and "1 appareil" in texte(p, "#e-moteur .det")
    assert texte(p, "#pastille-global") == "ACTIF" and p.get_attribute("#direct", "data-etat") == "direct" and texte(p, "#direct-lib") == "EN DIRECT"
    assert [texte(p, i).replace("\u202f", " ") for i in ("#v-req", "#v-blq", "#v-taux", "#v-cli", "#v-dom")] == ["100", "20", "20,0 %", "4", "412 800"]
    assert "400" in texte(p, "#top-barres") and "pub.exemple.test" in texte(p, "#top-barres") and "propre.exemple.test" not in texte(p, "#top-barres")
    assert p.locator("#courbe svg path").count() >= 2 and p.locator("#courbe svg rect").count() == 30
    assert "mis à jour il y a" in texte(p, "#maj") and err == []
    ctx.close()


def test_chaque_etat_porte_un_mot_et_une_icone_pas_seulement_la_couleur(navigateur):
    ctx, p, _, _ = ouvre(navigateur, {**api_nominale(), "/statut-direct": (200, etat(resolveur={"actif": False}))})
    attend(p, 1)
    assert texte(p, "#e-resolveur .mot") == "Unbound arrêté" and texte(p, "#e-resolveur .pt") == "✕" and "ko" in p.get_attribute("#e-resolveur", "class").split()
    assert texte(p, "#pastille-global") == "PANNE"
    ctx.close()


def test_puits_inactif_passe_en_orange(navigateur):
    ctx, p, _, _ = ouvre(navigateur, {**api_nominale(), "/statut-direct": (200, etat(puits={"actif": False, "ok": True, "erreur": None, "recharge": True}))})
    attend(p, 1)
    assert texte(p, "#e-puits .mot") == "Puits inactif" and "warn" in p.get_attribute("#e-puits", "class").split()
    assert texte(p, "#pastille-global") == "À SURVEILLER" and "warn" in p.get_attribute("#pastille-global", "class").split()
    ctx.close()


def test_listes_perimees_en_orange_avec_leur_age(navigateur):
    ctx, p, _, _ = ouvre(navigateur, {**api_nominale(), "/statut-direct": (200, etat(listes={"domaines": 412800, "maj_ts": NOW - 12 * 86400, "peremption_s": 9 * 86400}))})
    attend(p, 1)
    assert texte(p, "#e-listes .mot") == "Listes périmées" and "12 j" in texte(p, "#e-listes .det") and "warn" in p.get_attribute("#e-listes", "class").split()
    assert "12 j" in texte(p, "#n-dom")
    ctx.close()


def test_valeur_inconnue_reste_inconnue(navigateur):
    inconnu = etat(resolveur={"actif": None}, listes={"domaines": None, "maj_ts": None, "peremption_s": 9 * 86400}, clients={"actifs_5min": None, "vus": None})
    ctx, p, _, _ = ouvre(navigateur, {**api_nominale(), "/statut-direct": (200, inconnu), "/adblock-tv/serie": (200, {"pas_s": 60, "points": []})})
    attend(p, 1)
    assert texte(p, "#e-resolveur .mot") == "INCONNU" and "inc" in p.get_attribute("#e-resolveur", "class").split()
    assert [texte(p, i) for i in ("#v-req", "#v-blq", "#v-taux", "#v-cli", "#v-dom")] == ["—"] * 5
    assert "Aucune requête" in texte(p, "#courbe")
    ctx.close()


def test_api_qui_tombe_devient_hors_ligne_puis_revient(navigateur):
    panne = []
    ctx, p, err, appels = ouvre(navigateur, api_nominale(), panne=panne)
    attend(p, 1)
    assert p.get_attribute("#direct", "data-etat") == "direct"
    panne.append(1)
    p.clock.run_for(8000)
    p.wait_for_function("() => LIVE.echecs >= 1")
    assert p.get_attribute("#direct", "data-etat") == "direct"           # un seul échec : on ré-essaie, on ne crie pas
    p.clock.run_for(16000)                                               # retombée douce : le ré-essai est espacé (16 s)
    p.wait_for_function("() => LIVE.hors")
    assert p.get_attribute("#direct", "data-etat") == "hors" and texte(p, "#direct-lib") == "HORS LIGNE" and texte(p, "#pastille-global") == "HORS LIGNE"
    assert "perime" in p.get_attribute("#bande", "class").split() and p.evaluate("LIVE.echecs") >= 2
    avant = rel(appels)
    panne.clear()
    p.clock.run_for(32000)
    p.wait_for_function("() => !LIVE.hors && LIVE.echecs === 0")
    assert p.get_attribute("#direct", "data-etat") == "direct" and rel(appels) > avant and err == []
    ctx.close()


def test_api_absente_des_l_ouverture_affiche_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, api_nominale(), panne=[1])
    p.wait_for_function("() => LIVE.hors")
    assert texte(p, "#direct-lib") == "HORS LIGNE" and texte(p, "#v-req") == "—" and err == []
    ctx.close()


def test_rafraichissement_automatique_un_second_releve(navigateur):
    routes = api_nominale()
    ctx, p, _, appels = ouvre(navigateur, routes)
    attend(p, 1)
    assert nb(appels, "/statut-direct") == 1 and nb(appels, "/adblock-tv/serie#direct") == 1 and texte(p, "#v-req") == "100"
    routes["/adblock-tv/serie"] = (200, serie(cur=(200, 50), prev=(100, 20)))
    routes["/statut-direct"] = (200, etat(clients={"actifs_5min": 6, "vus": 9}))
    avance(p, 8000, 2)
    assert nb(appels, "/statut-direct") == 2 and nb(appels, "/adblock-tv/serie#direct") == 2
    assert [texte(p, "#v-req"), texte(p, "#v-blq"), texte(p, "#v-taux"), texte(p, "#v-cli")] == ["200", "50", "25,0 %", "6"]
    assert nb(appels, "/adblock-tv/flux#direct") == 1                           # les relevés lourds ne suivent pas le rythme rapide
    ctx.close()


def test_horloge_mis_a_jour_il_y_a_n_secondes_avance(navigateur):
    ctx, p, _, _ = ouvre(navigateur, api_nominale())
    attend(p, 1)
    p.clock.run_for(3000)
    assert texte(p, "#maj") == "mis à jour il y a 3 s"
    p.clock.run_for(2000)
    assert texte(p, "#maj") == "mis à jour il y a 5 s"
    ctx.close()


def test_onglet_masque_suspend_les_releves(navigateur):
    ctx, p, _, appels = ouvre(navigateur, api_nominale())
    attend(p, 1)
    p.evaluate("() => { Object.defineProperty(document, 'hidden', { value: true, configurable: true }); document.dispatchEvent(new Event('visibilitychange')); }")
    assert p.get_attribute("#direct", "data-etat") == "masque"
    n = rel(appels)
    p.clock.run_for(60000)
    p.wait_for_timeout(200)
    assert rel(appels) == n
    p.evaluate("() => { Object.defineProperty(document, 'hidden', { value: false, configurable: true }); document.dispatchEvent(new Event('visibilitychange')); }")
    p.clock.run_for(100)
    p.wait_for_function("() => LIVE.tick >= 2")
    assert rel(appels) > n and p.get_attribute("#direct", "data-etat") == "direct"
    ctx.close()


def test_pause_et_saisie_suspendent_les_releves(navigateur):
    ctx, p, _, appels = ouvre(navigateur, api_nominale())
    attend(p, 1)
    p.click("#btn-pause")
    assert texte(p, "#btn-pause") == "Reprendre" and p.get_attribute("#direct", "data-etat") == "pause"
    n = rel(appels)
    p.clock.run_for(40000)
    p.wait_for_timeout(200)
    assert rel(appels) == n
    p.click("#btn-pause")
    p.wait_for_function("() => LIVE.tick >= 2")
    # saisie : un champ texte rempli et ayant le focus retient les relevés
    p.evaluate("document.getElementById('avance').open = true")
    p.fill("#check-domain-input", "exemple.test")
    n = rel(appels)
    p.clock.run_for(40000)
    p.wait_for_timeout(200)
    assert rel(appels) == n
    p.fill("#check-domain-input", "")
    p.clock.run_for(2000)
    p.wait_for_function("() => LIVE.tick >= 3")
    assert rel(appels) > n
    ctx.close()


def test_confirmation_ouverte_suspend_les_releves(navigateur):
    ctx, p, _, appels = ouvre(navigateur, api_nominale())
    attend(p, 1)
    p.evaluate("() => { document.getElementById('avance').open = true; confirmer('Test ?'); }")
    p.wait_for_selector("#dialogue:not([hidden])")
    n = rel(appels)
    p.clock.run_for(40000)
    p.wait_for_timeout(200)
    assert rel(appels) == n
    ctx.close()


def test_variations_calculees_sur_deux_releves_reels(navigateur):
    ctx, p, _, _ = ouvre(navigateur, api_nominale())
    attend(p, 1)
    assert texte(p, "#d-req") == "↑ 25 %" and texte(p, "#d-blq") == "↑ 100 %" and texte(p, "#d-taux") == "↑ 7,5 pt"
    assert "80" in p.get_attribute("#d-req", "title")
    assert p.evaluate("variation(10, 8)") == {"sens": 1, "pct": 25} and p.evaluate("variation(6, 8)") == {"sens": -1, "pct": 25}
    assert p.evaluate("variation(100, 100.4)") == {"sens": 0, "pct": 0}
    assert p.evaluate("variation(5, 0)") is None and p.evaluate("variation(null, 5)") is None and p.evaluate("variation(5, null)") is None
    assert p.evaluate("variationPts(20, null)") is None
    ctx.close()


def test_pas_de_variation_sans_base_et_pas_de_variation_clients_avant_5_minutes(navigateur):
    routes = {**api_nominale(), "/adblock-tv/serie": (200, serie(prev=(0, 0)))}
    ctx, p, _, _ = ouvre(navigateur, routes)
    attend(p, 1)
    assert texte(p, "#v-req") == "100" and texte(p, "#d-req") == "" and texte(p, "#d-blq") == "" and texte(p, "#d-taux") == ""
    assert texte(p, "#d-cli") == ""                                       # un seul relevé de la page : rien à comparer
    # un relevé de la page vieux de plus de 5 minutes existe : la variation apparaît, calculée dessus
    p.evaluate("() => { LIVE.releves.unshift({ t: maintenantServeur() - 400, clients: 2 }); rendreTuiles(); }")
    assert texte(p, "#d-cli") == "↑ 100 %"
    ctx.close()


def test_baisse_et_stable(navigateur):
    routes = {**api_nominale(), "/adblock-tv/serie": (200, serie(cur=(50, 10), prev=(100, 10)))}
    ctx, p, _, _ = ouvre(navigateur, routes)
    attend(p, 1)
    assert texte(p, "#d-req") == "↓ 50 %" and texte(p, "#d-blq") == "→ stable" and texte(p, "#d-taux").startswith("↑")
    ctx.close()


def test_demonstration_annoncee_vivante_et_sans_requete(navigateur):
    ctx, p, err, appels = ouvre(navigateur, {}, query="?demo=1")
    attend(p, 1)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in texte(p, "#demo")
    assert texte(p, "#v-req") not in ("", "—") and texte(p, "#direct-lib") == "EN DIRECT" and "exemple.test" in texte(p, "#top-barres")
    avant = [texte(p, i) for i in ("#v-req", "#v-cli", "#v-taux")] + [p.evaluate("[...document.querySelectorAll('#top-barres .barre i')].map(e => e.style.width).join()")]
    for k in range(2, 6):
        avance(p, 8000, k)
    apres = [texte(p, i) for i in ("#v-req", "#v-cli", "#v-taux")] + [p.evaluate("[...document.querySelectorAll('#top-barres .barre i')].map(e => e.style.width).join()")]
    assert avant != apres
    assert [a for a in appels] == [] and err == []
    ctx.close()


def test_telephone_420_sans_debordement_embed(navigateur):
    ctx, p, err, _ = ouvre(navigateur, api_nominale(), query="?embed=1", taille={"width": 420, "height": 800})
    attend(p, 1)
    p.evaluate("document.getElementById('avance').open = true")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_telephone_420_demo_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, {}, query="?demo=1", taille={"width": 420, "height": 800})
    attend(p, 1)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert p.evaluate("[...document.querySelectorAll('.cadre *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1 && !e.closest('.defile')).length") == 0
    assert err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2658 — sept cartes du Hall au profil Aurora (activite, actor, coffre, comptes, cumul, dpi, ephemeride) :
partie statique pour chacune, puis un vrai navigateur (Chromium, API simulée sur http://sbx.test, données factices).

Les cartes sont encadrées dans une page parente de même origine, comme dans le Hall : on y lit les messages postés (hauteur, liens)."""
import json
import mimetypes
import re
import time
from pathlib import Path

import pytest

HALL = Path(__file__).resolve().parents[1] / "www" / "hall"
CARTES = ["activite", "actor", "coffre", "comptes", "cumul", "dpi", "ephemeride"]
SRC = {n: (HALL / "cardlets" / f"{n}.html").read_text(encoding="utf-8") for n in CARTES}
# Scripts partagés du Hall que les cartes chargeaient déjà : la garde des sondes, le slicer, l'aide, le domaine de la box.
PARTAGES = {"../sonde.js", "../slicebar.js", "../aide.js", "../domaine.js", "/api/v1/webos/public/hotes.js"}
# L'API lue par chaque carte, à l'identique de l'ancienne.
ROUTES = {
    "activite": ["/api/v1/sbxid/activite?n=30"],
    "actor": ["/api/v1/actor/stats", "/api/v1/actor/actors", "/api/v1/actor/overview", "/api/v1/actor/mesures", "/api/v1/acces/session/etat"],
    "coffre": ["/api/v1/vault/etat"],
    "comptes": ["/api/v1/sbxid/moi"],
    "cumul": ["/api/v1/webos/public", "/cardlets/waf", "/waf/qui-frappe", "/api/v1/webos/public/actions/"],
    "dpi": ["/api/v1/dpi/stats", "/api/v1/dpi/usage", "/api/v1/dpi/suggestions", "/api/v1/dpi/countries", "/api/v1/dpi/clients"],
    "ephemeride": ["/api/v1/ephemeride/"],
}


# ── statique ──────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("nom", CARTES)
def test_page_autonome_au_profil_aurora(nom):
    s = SRC[nom]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s and "<title>" in s and 'lang="fr"' in s
    assert "--fond:#060d1b" in s and "--cyan:#29b6f6" in s and "--rouge:#ff4d5e" in s       # jetons Aurora, à l'identique
    assert "hybrid-dark" not in s and "spicy.css" not in s and "lorem" not in s.lower()
    assert "[hidden]{display:none!important}" in s.replace(" ", "")
    srcs = set(re.findall(r'<script src="([^"]+)"', s))
    assert srcs <= PARTAGES, srcs - PARTAGES
    # aucune ressource externe : ni attribut src/href, ni fetch, ni url() vers une adresse absolue (les liens de service du Hall sont construits, pas chargés)
    assert not re.search(r"""(?:src|href)=["']https?://|fetch\(["']https?://|url\(["']?https?://""", s)


@pytest.mark.parametrize("nom", CARTES)
def test_aucun_dialogue_natif_ni_html_injecte(nom):
    s = SRC[nom]
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "Math.random"):
        assert interdit not in s, interdit
    assert "textContent" in s and not re.search(r"\son(click|load|error)=\"", s)


@pytest.mark.parametrize("nom", CARTES)
def test_demo_et_embed_declares(nom):
    s = SRC[nom]
    assert "get('demo')" in s and "DEMO" in s
    assert "DONNÉES DE DÉMONSTRATION" in s or "DÉMONSTRATION" in s
    if nom != "cumul":
        assert "get('embed')" in s
    assert "—" in s, "mesure absente = « — »"


@pytest.mark.parametrize("nom", [n for n in CARTES if n != "cumul"])
def test_hauteur_annoncee_au_hall(nom):
    s = SRC[nom]
    assert f"ONGLET_NOM = '{nom}'" in s
    assert "parent.postMessage({sbxVue: Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY), onglet: ONGLET_NOM}, location.origin)" in s
    assert "scrollHeight" not in s and "100vh" not in s
    assert "new ResizeObserver(annoncer)" in s


def test_la_carte_cumulative_remplit_son_cadre_et_n_annonce_pas_de_hauteur():
    assert "n'annonce donc pas de hauteur (sbxVue)" in SRC["cumul"] and "postMessage({sbxVue" not in SRC["cumul"]
    assert "ResizeObserver" not in SRC["cumul"] and ".cadre{height:100%}" in SRC["cumul"]


@pytest.mark.parametrize("nom", [n for n in CARTES if n != "ephemeride"])
def test_lecture_seule_aucune_ecriture(nom):
    s = SRC[nom]
    assert not re.search(r"method\s*:\s*['\"](POST|PUT|PATCH|DELETE)", s) and "'POST'" not in s and "'PUT'" not in s and "'DELETE'" not in s


def test_l_ephemeride_ecrit_a_l_identique_et_pas_en_demo():
    s = SRC["ephemeride"]
    assert "envoie(edition ? 'PUT' : 'POST', API + 'observations' + (edition ? '/' + edition.id : ''), {texte: t})" in s
    assert "envoie('DELETE', API + 'observations/' + edition.id)" in s
    assert s.count("if (DEMO){ inerte(); return; }") == 2
    assert "timeZone: D.fuseau.nom" in s and "serveur_epoch_ms" in s


@pytest.mark.parametrize("nom", CARTES)
def test_memes_routes_d_api(nom):
    for r in ROUTES[nom]:
        assert r in SRC[nom], r


def test_activite_garde_ses_messages_et_ses_liens_fermes():
    s = SRC["activite"]
    assert "parent.postMessage({ sbx: l.dataset.sbx, url: l.href, titre: l.textContent }, location.origin)" in s
    assert 'if (d && d.sbx === "relis") charge();' in s
    assert "function cible(a){" in s and "function ligne(a){" in s and "/^\\/bbs\\/(t|f)\\/([A-Za-z0-9_-]{1,64})$/" in s


def test_cumul_garde_ses_groupes_et_son_relais():
    s = SRC["cumul"]
    for g in ("securite:", "contenu:", "cloud:", "forums:"):
        assert g in s
    assert "get('groupe') || 'securite'" in s
    for u in ("/cardlets/actor.html", "/cardlets/quick.html?svc=depot", "svc=ytsas", "svc=torrent", "svc=nextcloud", "svc=photoprism", "svc=mail", "/micro"):
        assert u in s
    assert "['ouvre-hote', 'surf', 'surf-close', 'surf-vide', 'surf-hote'," in s and "'voir', 'valider', 'connexion', 'contexte']" in s
    assert "parent.postMessage({ sbx: 'ouvre-hote', hote: host, url: 'https://' + host + '/' }, '*')" in s
    assert "ev.source !== fe.contentWindow" in s


def test_actor_garde_ses_cinq_couches_et_son_score():
    s = SRC["actor"]
    for i in ("d-vue", "d-even", "d-acteurs", "d-profil", "d-defense"):
        assert f'id="{i}"' in s
    assert "function score(" in s and "p>=70" in s and "p>=45" in s


# ── navigateur ────────────────────────────────────────────────────────────────────────────────────────────────────────
playwright = pytest.importorskip("playwright.sync_api")
NOW = int(time.time())


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


PARENT = """<!doctype html><meta charset="utf-8"><body style="margin:0"><iframe id="f" name="c" style="width:420px;height:700px;border:0"></iframe>
<script>window.__recus=[];addEventListener('message',function(e){window.__recus.push({d:e.data,o:e.origin});});
document.getElementById('f').src=new URLSearchParams(location.search).get('src');</script>"""


def ouvre(nav, nom, query="", routes=None, largeur=420):
    """Ouvre la carte dans un cadre de même origine. Renvoie (contexte, page parente, cadre, erreurs JS, appels d'API)."""
    ctx = nav.new_context(viewport={"width": largeur, "height": 800})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route("https://**", lambda r: r.abort())

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin == "__parent.html":
            r.fulfill(status=200, content_type="text/html", body=PARENT)
        elif chemin == "sonde.js" or chemin == "api/v1/webos/public/hotes.js":
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin.startswith("api/"):
            appels.append((r.request.method, "/" + chemin, r.request.post_data))
            statut, corps = (routes or {}).get("/" + chemin, (404, {}))
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
        elif (HALL / chemin).is_file():
            f = HALL / chemin
            r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/__parent.html?src=" + f"/cardlets/{nom}.html{query}".replace("?", "%3F").replace("&", "%26").replace("=", "%3D"))
    cadre = None
    for _ in range(100):
        cadre = p.frame(name="c")
        if cadre and cadre.url.startswith("http://sbx.test/cardlets/"):
            break
        p.wait_for_timeout(50)
    cadre.wait_for_load_state("domcontentloaded")
    return ctx, p, cadre, erreurs, appels


def recus(p):
    return p.evaluate("window.__recus")


def attend_hauteur(p, nom):
    p.wait_for_function("window.__recus.some(m => m.d && m.d.sbxVue)")
    m = [x for x in recus(p) if x["d"] and "sbxVue" in x["d"]]
    assert all(x["o"] == "http://sbx.test" and x["d"]["onglet"] == nom for x in m)
    h = m[-1]["d"]["sbxVue"]
    assert isinstance(h, int) and 80 <= h <= 4000, h
    return h


def sans_debordement(f):
    assert f.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def textes(f, sel):
    return [t.strip() for t in f.locator(sel).all_text_contents()]


# ── démonstration : 420 px, bandeau, aucune requête, hauteur annoncée ───────────────────────────────────────────────
@pytest.mark.parametrize("nom", CARTES)
def test_demo_420_sans_debordement_ni_appel_ni_erreur(nav, nom):
    q = "?demo=1&niveau=etendu" if nom == "ephemeride" else "?demo=1"
    ctx, p, f, err, appels = ouvre(nav, nom, q)
    f.wait_for_selector("#demo:not([hidden])")
    assert "DÉMONSTRATION" in f.inner_text("#demo")
    p.wait_for_timeout(300)
    sans_debordement(f)
    if nom != "cumul":
        attend_hauteur(p, nom)
    assert appels == [], appels
    assert err == []
    ctx.close()


def test_demo_activite_liens_inertes(nav):
    ctx, p, f, err, appels = ouvre(nav, "activite", "?demo=1")
    f.wait_for_selector("#liste li a[data-sbx]")
    f.click("#liste li a[data-sbx]")
    f.wait_for_selector("#retour:not([hidden])")
    assert "inerte" in f.inner_text("#retour")
    assert not [m for m in recus(p) if m["d"] and m["d"].get("sbx")] and appels == [] and err == []
    ctx.close()


def test_demo_comptes_liens_inertes(nav):
    ctx, p, f, err, appels = ouvre(nav, "comptes", "?demo=1")
    f.wait_for_selector("a.cpt")
    f.click("a.cpt >> nth=0")
    f.wait_for_selector("#retour:not([hidden])")
    assert "inerte" in f.inner_text("#retour") and appels == [] and err == []
    ctx.close()


def test_demo_ephemeride_ecriture_inerte(nav):
    ctx, p, f, err, appels = ouvre(nav, "ephemeride", "?demo=1&niveau=etendu")
    f.wait_for_selector("#obs-note")
    f.click("#obs-plus")
    f.fill("#obs-texte", "essai")
    f.click("#obs-ok")
    f.wait_for_function("document.getElementById('obs-msg').textContent.includes('inerte')")
    f.click("#obs-suppr")
    assert appels == [] and err == []
    ctx.close()


def test_demo_actor_remplit_les_couches_sans_requete(nav):
    ctx, p, f, err, appels = ouvre(nav, "actor", "?demo=1")
    f.wait_for_function("document.getElementById('t-crit').textContent !== '—'")
    assert textes(f, "#t-crit, #t-susp, #t-obs") == ["2", "1", "2"]
    assert f.inner_text("#etat") == "SHADOW · OBSERVE"
    assert f.locator("#crans .cran.on").count() >= 2 and appels == [] and err == []
    ctx.close()


@pytest.mark.parametrize("groupe,fragment", [("contenu", "/cardlets/quick.html?svc=depot"), ("cloud", "svc=nextcloud"), ("forums", "/micro")])
def test_demo_cumul_groupes_embarques(nav, groupe, fragment):
    ctx, p, f, err, appels = ouvre(nav, "cumul", f"?demo=1&groupe={groupe}")
    f.wait_for_selector("#corps iframe", state="attached")
    src = f.get_attribute("#corps iframe", "src")
    assert fragment in src and "embed=1" in src and "demo=1" in src
    assert f.evaluate("document.getElementById('mw').classList.contains('embed')")
    sans_debordement(f)
    assert err == []
    ctx.close()


# ── données simulées ──────────────────────────────────────────────────────────────────────────────────────────────────
def test_activite_donnees_texte_seul_et_message_au_hall(nav):
    acts = [{"kind": "bbs_post", "qui": "bbs:bob", "at": NOW - 60, "visibility": "public", "context": {"titre": "<b>gras</b>", "lien": "/bbs/t/1129"}},
            {"kind": "user_joined", "qui": "alice", "at": NOW - 7200, "visibility": "community", "community_name": "Atelier"}]
    ctx, p, f, err, _ = ouvre(nav, "activite", "", {"/api/v1/sbxid/activite": (200, {"activites": acts})})
    f.wait_for_selector("#liste li a[data-sbx]")
    assert textes(f, "#tN, #tPublic, #tCom") == ["2", "1", "1"] and f.inner_text("#tDernier") == "à l'instant"
    assert f.locator("#liste b").count() == 0 and "<b>gras</b>" in f.inner_text("#liste")
    assert f.inner_text("#etat") == "À JOUR"
    f.click("#liste a[data-sbx]")
    p.wait_for_function("window.__recus.some(m => m.d && m.d.sbx === 'surf')")
    m = [x for x in recus(p) if x["d"].get("sbx") == "surf"][0]
    assert m["o"] == "http://sbx.test" and m["d"]["url"].endswith("/t/1129") and m["d"]["url"].startswith("https://") and "gras" in m["d"]["titre"]
    sans_debordement(f)
    ctx.close()


def test_activite_liste_vide_et_sans_session(nav):
    ctx, p, f, err, _ = ouvre(nav, "activite", "", {"/api/v1/sbxid/activite": (200, {"activites": []})})
    f.wait_for_selector("#msg:not([hidden])")
    assert "Rien encore" in f.inner_text("#msg") and f.inner_text("#etat") == "AUCUN GESTE" and f.inner_text("#tDernier") == "—"
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "activite", "", {"/api/v1/sbxid/activite": (401, {"detail": "jeton requis"})})
    f.wait_for_selector("#session:not([hidden])")
    assert "session requise" in f.inner_text("#session") and textes(f, "#tN, #tDernier, #tPublic, #tCom") == ["—"] * 4 and err == []
    ctx.close()


ETAT = {"initialise": True, "ouvert": True, "reste_s": 65, "journal": {"integre": True, "lignes": 12},
        "serrures": [{"genre": "mot_de_passe"}, {"genre": "appareil"}], "compartiments": [{"secrets": 3}, {"secrets": 4}]}


def test_coffre_etat_ouvert_scelle_et_altere(nav):
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (200, ETAT)})
    f.wait_for_function("document.getElementById('k-secrets').textContent !== '—'")
    assert textes(f, "#k-secrets, #k-serrures, #k-appareils, #k-journal") == ["7", "2", "1", "✓ 12"]
    assert f.inner_text("#etat") == "OUVERT · 1:05" and "1:05" in f.inner_text("#note")
    sans_debordement(f)
    ctx.close()
    scelle = {**ETAT, "ouvert": False, "journal": {"integre": False, "ligne_fautive": 7}}
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (200, scelle)})
    f.wait_for_function("document.getElementById('etat').textContent === 'JOURNAL ALTÉRÉ'")
    assert f.inner_text("#k-journal") == "⚠ l.7" and "ko" in f.get_attribute("#kpi-journal", "class")
    assert err == []
    ctx.close()


def test_coffre_sans_session_non_initialise_et_hors_ligne(nav):
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (403, {})})
    f.wait_for_selector("#session:not([hidden])")
    assert f.inner_text("#etat") == "RÉSERVÉ" and textes(f, "#k-secrets, #k-serrures, #k-appareils, #k-journal") == ["—"] * 4
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (200, {"initialise": False})})
    f.wait_for_function("document.getElementById('etat').textContent === 'NON INITIALISÉ'")
    assert "naîtra" in f.inner_text("#note")
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (500, {})})
    f.wait_for_function("document.getElementById('etat').textContent === 'INJOIGNABLE'")
    assert err == []
    ctx.close()


def test_coffre_mesure_absente_est_un_tiret_pas_un_zero(nav):
    ctx, p, f, err, _ = ouvre(nav, "coffre", "", {"/api/v1/vault/etat": (200, {"initialise": True, "ouvert": False})})
    f.wait_for_function("document.getElementById('etat').textContent === 'SCELLÉ'")
    assert textes(f, "#k-secrets, #k-serrures, #k-appareils, #k-journal") == ["—"] * 4
    ctx.close()


def test_comptes_liens_et_texte_seul(nav):
    moi = {"identite": {"pseudo": "<i>gek</i>"}, "liens": [{"app": "nextcloud", "app_handle": "gek"}, {"app": "gitea", "app_handle": "gek-git"}, {"app": "inconnu", "app_handle": "x"}]}
    ctx, p, f, err, _ = ouvre(nav, "comptes", "", {"/api/v1/sbxid/moi": (200, moi)})
    f.wait_for_selector("a.cpt")
    assert f.locator("a.cpt").count() == 3                                # nextcloud, gitea, photoprism (OIDC) ; « inconnu » écarté
    assert f.inner_text("#qui") == "<i>gek</i>" and f.locator("#qui i").count() == 0
    assert textes(f, "#tN, #tPassif") == ["3", "2"]
    hrefs = [a.get_attribute("href") for a in f.locator("a.cpt").all()]
    assert "https://nc.sbx.test/sbx/entrer" in hrefs and "https://git.sbx.test/" in hrefs and "https://photoprism.sbx.test/api/v1/oidc/login" in hrefs
    sans_debordement(f)
    ctx.close()


def test_comptes_sans_session_et_sans_identite(nav):
    ctx, p, f, err, _ = ouvre(nav, "comptes", "", {"/api/v1/sbxid/moi": (401, {})})
    f.wait_for_selector("#session:not([hidden])")
    assert f.inner_text("#etat") == "SESSION REQUISE" and textes(f, "#tN, #tPassif") == ["—", "—"] and err == []
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "comptes", "", {"/api/v1/sbxid/moi": (200, {"identite": None, "liens": []})})
    f.wait_for_function("document.getElementById('etat').textContent === 'SANS IDENTITÉ'")
    assert f.locator("a.cpt").count() == 0
    ctx.close()


def eph(**mod):
    j0 = NOW - NOW % 86400
    def iso(s):
        return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(s))
    d = {"serveur_epoch_ms": NOW * 1000,
         "calendrier": {"jour_semaine": "mercredi", "jour": "14", "mois": "octobre", "annee": "2026", "semaine_iso": 42, "jour_annee": 287, "saison": "automne",
                        "saison_debut": "2026-09-23", "jours_avant_saison_suivante": 68},
         "lieu": {"nom": "Lieu fictif", "approximatif": False, "latitude": 45.0, "longitude": 6.0}, "fuseau": {"nom": "Europe/Paris", "decalage": "UTC+02:00"},
         "soleil": {"etat": "jour", "lever": iso(j0 + 6 * 3600), "coucher": iso(j0 + 18 * 3600), "duree_s": 43200, "progression": 0.5},
         "lune": {"nom": "pleine lune", "illumination": 99, "croissante": True, "age_jours": 14.8, "lever": iso(j0 + 17 * 3600), "coucher": iso(j0 + 30 * 3600),
                  "prochaine_phase": {"nom": "Dernier quartier", "quand": iso(j0 + 6 * 86400)}},
         "saints": [{"nom": "Saint Exemple", "description": "Fictif"}], "meteo": {"temperature_c": 12.4, "condition": "Pluie", "vent_kmh": 9}, "meteo_etat": {"etat": "ok"},
         "air": {"niveau": "Bon", "indice": 30, "polluant_principal": "O3"}, "air_etat": {"etat": "ok"}, "observations": [],
         "reglages": {"observations": True, "format_24h": True}}
    d.update(mod)
    return d


def test_ephemeride_rend_les_donnees_et_dit_l_absence(nav):
    ctx, p, f, err, _ = ouvre(nav, "ephemeride", "?niveau=etendu", {"/api/v1/ephemeride/": (200, eph(meteo=None, meteo_etat={"etat": "indisponible"}, air=None, air_etat={"etat": "desactive"}))})
    f.wait_for_function("document.getElementById('jour').textContent.includes('2026')")
    assert f.inner_text("#jour") == "Mercredi 14 octobre 2026" and f.inner_text("#saint-nom") == "Saint Exemple"
    assert f.inner_text("#meteo") == "Indisponible" and "Météo indisponible" in f.inner_text("#meteo-s") and f.inner_text("#air") == "Désactivée"
    assert re.fullmatch(r"\d\d:\d\d:\d\d", f.inner_text("#heure").strip())
    assert f.inner_text("#etat") == "À JOUR" and "Pleine lune" in f.inner_text("#lune-nom")
    assert f.get_attribute("#eph", "data-niveau") == "etendu"
    sans_debordement(f)
    ctx.close()


def test_ephemeride_enregistre_une_observation_a_l_identique(nav):
    routes = {"/api/v1/ephemeride/": (200, eph()), "/api/v1/ephemeride/observations": (200, {"id": "n1"})}
    ctx, p, f, err, appels = ouvre(nav, "ephemeride", "?niveau=etendu", routes)
    f.wait_for_function("document.getElementById('jour').textContent.includes('2026')")
    f.click("#obs-plus")
    f.fill("#obs-texte", "Ciel clair")
    f.click("#obs-ok")
    p.wait_for_timeout(300)
    posts = [a for a in appels if a[0] == "POST"]
    assert posts == [("POST", "/api/v1/ephemeride/observations", '{"texte":"Ciel clair"}')]
    assert err == []
    ctx.close()


def test_ephemeride_sans_session_et_non_installee(nav):
    ctx, p, f, err, _ = ouvre(nav, "ephemeride", "", {"/api/v1/ephemeride/": (401, {})})
    f.wait_for_selector("#session:not([hidden])")
    assert "Connectez-vous" in f.inner_text("#etat-donnees") and f.inner_text("#etat") == "SESSION REQUISE" and f.inner_text("#jour") == "—"
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "ephemeride", "", {"/api/v1/ephemeride/": (502, {})})
    f.wait_for_function("document.getElementById('etat-donnees').textContent.includes('non installée')")
    assert err == []
    ctx.close()


ID_PIEGE = "<img src=x onerror=window.__x=1>"
ACTORS = [{"id": ID_PIEGE, "bans": 4, "src": {"ips": 16, "countries": 4}, "vec": {"continuity": 100, "persistence": 100, "automation": 100}, "tags": [["auto", "auto"]],
           "first": "avant-hier", "last": "ce matin"},
          {"id": "ACT-2", "src": {"ips": 1, "countries": 1}, "vec": {}}]


def api_actor(**mod):
    r = {"/api/v1/acces/session/etat": (200, {"session": True}),
         "/api/v1/actor/stats": (200, {"actors": 2, "campaigns": 0, "mode": "observe"}),
         "/api/v1/actor/actors": (200, ACTORS),
         "/api/v1/actor/overview": (200, {"top_pays": [{"code": "NL", "n": 5}], "recents": [{"ts": NOW - 60, "acteur": "ACT-2", "type": "scan", "module": "waf", "score": 40}],
                                          "activite_acteurs": {}, "techniques": {}}),
         "/api/v1/actor/mesures": (200, {"par_niveau": {"DENY": 2}})}
    r.update(mod)
    return r


def test_actor_donnees_reelles_score_calcule_et_aucune_injection(nav):
    ctx, p, f, err, _ = ouvre(nav, "actor", "", api_actor())
    f.wait_for_function("document.getElementById('t-crit').textContent === '1'")
    assert textes(f, "#t-crit, #t-susp, #t-obs") == ["1", "0", "1"]
    assert textes(f, "#k-actors, #k-camp, #k-ev, #k-block") == ["2", "0", "—", "—"]       # mesures absentes : « — », 0 reste un 0
    assert f.inner_text("#etat") == "SHADOW · OBSERVE"
    assert f.evaluate("window.__x") is None and f.locator("#list img").count() == 0 and ID_PIEGE in f.text_content("#list")
    assert "2 acteur" in f.text_content("#crans") and f.locator("#carte circle.bulle").count() == 1
    assert "ACT-2" in f.text_content("#even") and f.locator("#session:not([hidden])").count() == 0
    sans_debordement(f)
    attend_hauteur(p, "actor")
    assert err == []
    ctx.close()


def test_actor_la_fiche_a_ses_trois_onglets(nav):
    ctx, p, f, err, _ = ouvre(nav, "actor", "", api_actor())
    f.wait_for_function("document.getElementById('t-crit').textContent === '1'")
    f.evaluate("document.querySelectorAll('.sbx-dots button')[3].click()")
    f.wait_for_selector("#profile button[data-o=tech]")
    assert "Score" in f.text_content("#profile") and "Première détection" in f.text_content("#profile") and "Activité (24 h)" in f.text_content("#profile")
    f.click("#profile button[data-o=tech]")
    assert "Pas de technique relevée" in f.text_content("#profile")
    f.click("#profile button[data-o=rep]")
    assert "shadow · propose" in f.text_content("#profile")
    assert err == []
    ctx.close()


def test_actor_sans_session_ne_montre_aucun_chiffre_invente(nav):
    ctx, p, f, err, _ = ouvre(nav, "actor", "", api_actor(**{"/api/v1/acces/session/etat": (200, {"session": False})}))
    f.wait_for_selector("#session:not([hidden])")
    assert "Ouvre une session pour voir le détail des acteurs." in f.inner_text("#bandes")
    assert textes(f, "#t-crit, #t-susp, #t-obs") == ["—"] * 3 and err == []
    ctx.close()


def test_actor_moteur_injoignable_est_dit(nav):
    ctx, p, f, err, _ = ouvre(nav, "actor", "", api_actor(**{"/api/v1/actor/stats": (503, {})}))
    f.wait_for_function("document.getElementById('etat').textContent === 'MOTEUR INJOIGNABLE'")
    assert "nouvel essai automatique" in f.text_content("#list") and err == []
    ctx.close()


def test_actor_embarquee_est_compacte_sans_second_slicer_ni_hauteur(nav):
    ctx, p, f, err, _ = ouvre(nav, "actor", "?embed=1", api_actor())
    f.wait_for_function("document.getElementById('t-crit').textContent === '1'")
    assert f.evaluate("document.documentElement.classList.contains('emb')") and not f.is_visible("#slbar") and not f.is_visible(".sec-t")
    assert f.locator(".sbx-bar").count() == 0 and sans_debordement(f) is None
    p.wait_for_timeout(300)
    assert not [m for m in recus(p) if m["d"] and "sbxVue" in m["d"]]                # cadre rempli : l'iframe cumulative ne défile pas
    ctx.close()


def stats_dpi(**mod):
    d = {"total_flows": 12, "total_bytes": 1000, "updated_at": 1, "protocols": [{"name": "TLS", "pct": 60}, {"name": "DNS", "pct": 30}], "apps": [], "categories": [],
         "talkers": [{"name": "a → b", "pct": 10, "src": {"nom": "<b>box</b>", "source": "soi", "portee": "soi"}, "dst": {"nom": "miroir", "source": "ptr"}}],
         "risks": [{"severity": "high", "name": "Certificat expiré", "count": 2}]}
    d.update(mod)
    return d


def test_dpi_lit_le_trafic_en_texte_seul(nav):
    ctx, p, f, err, _ = ouvre(nav, "dpi", "", {"/api/v1/dpi/stats": (200, stats_dpi())})
    f.wait_for_function("document.getElementById('etat').textContent === 'LIVE'")
    assert textes(f, "#k-flows, #k-risk") == ["12", "1"] and f.inner_text("#k-bw").startswith("…")
    assert "TLS" in f.text_content("#s-proto") and f.locator("#s-talk b").count() == 0 and "🏠<b>box</b> → ↩️miroir" in f.text_content("#s-talk")
    assert f.locator("#s-risk .risk.hi").count() == 1
    sans_debordement(f)
    attend_hauteur(p, "dpi")
    assert err == []
    ctx.close()


def test_dpi_sans_session_ou_en_veille_dit_tiret_et_etat(nav):
    ctx, p, f, err, _ = ouvre(nav, "dpi", "", {"/api/v1/dpi/stats": (401, {})})
    f.wait_for_selector("#session:not([hidden])")
    assert f.inner_text("#etat") == "SESSION REQUISE" and textes(f, "#k-flows, #k-bw, #k-risk") == ["—"] * 3 and err == []
    ctx.close()
    ctx, p, f, err, _ = ouvre(nav, "dpi", "", {"/api/v1/dpi/stats": (404, {})})
    f.wait_for_function("document.getElementById('etat').textContent === 'EN VEILLE'")
    assert not f.is_visible("#session") and textes(f, "#k-flows") == ["—"]
    ctx.close()


def test_dpi_mega_empile_toutes_les_sections(nav):
    ctx, p, f, err, _ = ouvre(nav, "dpi", "?demo=1&embed=1&mega=1", largeur=420)
    f.wait_for_selector("#s-clients .client")
    assert f.evaluate("document.querySelectorAll('.dsec').length") == 10 and f.is_visible("#d-learning") and f.is_visible("#d-infra") and not f.is_visible("#slbar")
    f.click("#s-clients .client >> nth=0")
    assert f.evaluate("document.querySelector('#s-clients .client').classList.contains('open')")
    sans_debordement(f)
    assert err == []
    ctx.close()


PUB_WAF = {"metrics": [{"id": "bans", "value": 5}, {"id": "jour", "value": 12}, {"id": "detections", "value": 0}], "content": {"title": "NL"}, "trend_jour": "down",
           "recent": [{"ip": "203.0.113.9", "country": "NL", "categorie": "scan"}]}
PUB_QF = {"ok": True, "attaquants": 7, "campagnes_total": 2, "haute_valeur": 1,
          "campagnes": [{"signature": ID_PIEGE, "attaquants": 3, "sondes": 50, "haute_valeur": 1, "outil": "x", "sequence": ["/a", "/b"]}]}


def test_cumul_securite_couches_natives_en_texte_seul(nav):
    routes = {"/api/v1/webos/public/cardlets/waf": (200, PUB_WAF), "/api/v1/webos/public/waf/qui-frappe": (200, PUB_QF)}
    ctx, p, f, err, _ = ouvre(nav, "cumul", "", routes)
    f.wait_for_selector(".kpis .tuile")
    assert textes(f, ".kpis .tuile .v") == ["5", "12▼", "—", "0"]                      # surfaces absente : « — », détections 0 : 0
    assert "NL" in f.inner_text(".sous") and "203.0.113.9" in f.inner_text(".iplist")
    f.evaluate("document.querySelectorAll('.sbx-dots button')[1].click()")
    f.wait_for_function("document.querySelector('.camp') !== null")
    assert textes(f, ".kpis .tuile .v") == ["7", "2", "1"] and f.locator("#corps img").count() == 0 and ID_PIEGE in f.text_content("#corps")
    f.evaluate("document.querySelectorAll('.sbx-dots button')[2].click()")
    f.wait_for_selector(".anl1")
    assert f.locator(".anseq1 .sqc").count() == 2
    sans_debordement(f)
    assert err == []
    ctx.close()


def test_cumul_pare_feu_injoignable_est_dit(nav):
    ctx, p, f, err, _ = ouvre(nav, "cumul", "", {})
    f.wait_for_function("document.querySelector('#corps .vide') !== null")
    assert "injoignable" in f.inner_text("#corps") and err == []
    ctx.close()

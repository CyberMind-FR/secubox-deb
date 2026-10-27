# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3212 — onglet « Validation du parc » de /profiles/comparatif.html : une ligne par paquet, une colonne par box.

Vrai navigateur, API simulée (annuaire /fleet/modules, profiles /validation), vraie feuille hybrid-skin. La page
n'invente aucun état : elle affiche ce que chaque box a signé, et nomme les box sans relevé lisible."""
import json
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "profiles" / "comparatif.html"
SKIN = PKG.parent / "secubox-hub" / "www" / "shared" / "hybrid-skin.css"
playwright = pytest.importorskip("playwright.sync_api")


def paquet(nom, etat="fonctionnel", version="1.0", **sur):
    return {"paquet": nom, "version": version if etat not in ("manquant", "absent") else None, "statut_dpkg": "ii",
            "installe": etat not in ("manquant", "absent"), "attendu": True, "recommande": False, "meta": False,
            "hors_profil": False, "etat": etat, "unites": [], "agregateur": [], "memoire_o": None, "cpu_pct": None,
            "erreurs": [], **sur}


def noeud(nom, paquets, profil="lite", stale=False, partiel=()):
    return {"hostname": nom, "node_did": "did:plc:" + nom.ljust(32, "0")[:32], "profil_actif": profil,
            "profils_installes": [profil], "releve_ts": "2026-10-27T10:00:00Z", "ts": "2026-10-27T10:00:30Z",
            "partiel": list(partiel), "stale": stale, "paquets": paquets}


FLOTTE = {"noeuds": [
    noeud("gk4", [paquet("secubox-p2p", version="1.19.1"), paquet("secubox-lyrion", "veille", hors_profil=True)], "isp",
          stale=True),
    noeud("gk2", [paquet("secubox-p2p", version="1.19.2", memoire_o=52428800),
                  paquet("secubox-mail", "erreur", erreurs=["secubox-mail-imap-sync.service en échec (exit-code)"]),
                  paquet("secubox-core")], "full", partiel=["agrégateur injoignable"]),
    noeud("gk3", [paquet("secubox-p2p", version="1.19.2"), paquet("secubox-gitea", "manquant",
                                                                     erreurs=["attendu par le profil lite, non installé"]),
                  paquet("secubox-core")]),
], "indisponibles": [{"nom": "gk1", "mesh_ip": "10.10.0.8", "raison": "version trop ancienne"}]}
LOCAL = noeud("gk2", [paquet("secubox-p2p", version="1.19.2"), paquet("secubox-core")], "full")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, flotte=FLOTTE, statut_flotte=200, url="http://sbx.test/profiles/comparatif.html#parc"):
    ctx = navigateur.new_context(viewport={"width": 1400, "height": 1000})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin == "shared/hybrid-skin.css":
            r.fulfill(status=200, content_type="text/css", body=SKIN.read_text(encoding="utf-8"))
        elif chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin == "profiles/comparatif.html":
            r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        appels.append(u)
        if u == "/api/v1/annuaire/fleet/modules":
            if statut_flotte != 200:
                return r.fulfill(status=statut_flotte, content_type="application/json", body='{"detail":"x"}')
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(flotte))
        corps = {"/api/v1/profiles/validation": LOCAL, "/api/v1/profiles/comparatif": {"profils": [], "dpkg": "ok"},
                 "/api/v1/profiles/status": {"modules": []}}.get(u)
        r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps or {}))
    p.route("http://sbx.test/api/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def cellule(p, ligne, box):
    return p.locator(f'#parc tr[data-paquet="{ligne}"] td[data-box="{box}"]')


def test_une_colonne_par_box_triee_et_les_indisponibles_nommes(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector("#parc th[data-box]")
    assert [t.split("\n")[0].strip() for t in p.locator("#parc thead th[data-box]").all_inner_texts()] == ["gk1", "gk2", "gk3", "gk4"]
    gk1 = p.inner_text('#parc thead th[data-box="gk1"]')
    assert "version trop ancienne" in gk1
    assert "périmé" in p.inner_text('#parc thead th[data-box="gk4"]')
    assert "partiel" in p.inner_text('#parc thead th[data-box="gk2"]')
    assert err == []
    ctx.close()


def test_chaque_cellule_porte_l_etat_signe_par_sa_box(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.locator("#fTous").click()
    p.wait_for_selector('#parc tr[data-paquet="secubox-mail"]')
    assert cellule(p, "secubox-mail", "gk2").get_attribute("data-etat") == "erreur"
    assert cellule(p, "secubox-gitea", "gk3").get_attribute("data-etat") == "manquant"
    assert cellule(p, "secubox-lyrion", "gk4").get_attribute("data-etat") == "veille"
    assert cellule(p, "secubox-lyrion", "gk2").get_attribute("data-etat") == "absent"    # pas dans son relevé
    assert cellule(p, "secubox-p2p", "gk1").get_attribute("data-etat") == "indisponible"
    assert "50 Mo" in cellule(p, "secubox-p2p", "gk2").inner_text()
    ctx.close()


def test_les_ecarts_de_version_sont_signales(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector('#parc tr[data-paquet="secubox-p2p"]')
    ligne = p.locator('#parc tr[data-paquet="secubox-p2p"]')
    assert "ecart-version" in (ligne.get_attribute("class") or "")
    assert "1.19.1" in cellule(p, "secubox-p2p", "gk4").inner_text()
    ctx.close()


def test_filtres_ecarts_par_defaut_puis_erreurs_puis_tous(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector("#parc tbody tr")
    lignes = lambda: sorted(p.locator("#parc tbody tr[data-paquet]").evaluate_all("l => l.map(x => x.dataset.paquet)"))  # noqa: E731
    # Écart = version différente, ou une box en erreur / arrêtée / manquante / inconnue. Un paquet absent d'une box dont
    # le profil ne le demande pas n'en est pas un (core absent du relevé de gk4, lyrion en veille hors profil).
    assert lignes() == ["secubox-gitea", "secubox-mail", "secubox-p2p"]
    p.locator("#fErreurs").click()
    assert lignes() == ["secubox-gitea", "secubox-mail"]
    p.locator("#fTous").click()
    assert lignes() == ["secubox-core", "secubox-gitea", "secubox-lyrion", "secubox-mail", "secubox-p2p"]
    ctx.close()


def test_les_erreurs_sont_listees_par_box(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector("#parcErreurs li")
    texte = p.inner_text("#parcErreurs")
    assert "gk2" in texte and "secubox-mail-imap-sync.service en échec" in texte and "gk3" in texte
    ctx.close()


def test_l_onglet_profils_reste_et_la_flotte_n_est_lue_qu_a_l_ouverture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, url="http://sbx.test/profiles/comparatif.html")
    p.wait_for_selector("#vueProfils:not([hidden])")
    assert p.locator("#vueParc").is_hidden() and "/api/v1/annuaire/fleet/modules" not in appels
    p.locator("#ongletParc").click()
    p.wait_for_selector("#parc th[data-box]")
    assert "/api/v1/annuaire/fleet/modules" in appels and p.locator("#vueProfils").is_hidden()
    ctx.close()


def test_sans_comparaison_du_parc_le_releve_local_reste_visible(navigateur):
    ctx, p, err, _ = ouvre(navigateur, statut_flotte=502)
    p.wait_for_selector("#parc th[data-box]")
    assert "indisponible" in p.inner_text("#parcAlerte").lower()
    assert [t.split("\n")[0].strip() for t in p.locator("#parc thead th[data-box]").all_inner_texts()] == ["gk2"]
    ctx.close()


def test_session_requise(navigateur):
    ctx, p, err, _ = ouvre(navigateur, statut_flotte=401)
    p.wait_for_selector("#session:not([hidden])")
    ctx.close()


def test_les_fonds_des_cellules_survivent_a_hybrid_skin(navigateur):
    ctx, p, err, _ = ouvre(navigateur)
    p.wait_for_selector('#parc td[data-etat="erreur"]')
    p.evaluate("document.body.classList.add('hybrid-skin'); const l=document.createElement('link'); l.rel='stylesheet'; l.href='/shared/hybrid-skin.css'; document.head.appendChild(l)")
    p.wait_for_timeout(400)
    fond = p.evaluate("getComputedStyle(document.querySelector('#parc td[data-etat=\"erreur\"]')).backgroundColor")
    assert fond not in ("rgba(0, 0, 0, 0)", "transparent")
    ctx.close()

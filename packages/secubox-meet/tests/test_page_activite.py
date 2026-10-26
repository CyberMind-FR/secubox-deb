# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3182 — onglets Réunions, Connexions, Statistiques de /meet/, dans un vrai navigateur avec API simulée."""
import json

import pytest

import test_page as P

pytest.importorskip("playwright.sync_api")
navigateur = P.navigateur                    # fixture partagée (un Chromium par module)

T0 = 1793002354
SALLE = "2c8ef9e1-ba03-407e-b506-339c292c7573"
AUTRE = "47d7d08c-b654-4a1c-a825-a553aaf5b0c0"
PIEGE = "<img src=x onerror=window.piege=1>"
REUNIONS = {"reunions": [
    {"salle": SALLE, "nom": "gii-cbvo-lpe", "slug": "gii-cbvo-lpe", "acces": "public", "proprietaire": "gandalf", "creee": T0 - 600,
     "derniere": {"debut": T0 - 300, "participants": 2, "secondes": 1440}, "en_cours": True, "presents": 2},
    {"salle": AUTRE, "nom": PIEGE, "slug": "yjw-dcvf-cja", "acces": "trusted", "proprietaire": None, "creee": T0 - 7200,
     "derniere": None, "en_cours": False, "presents": 0}], "releve": T0}
DIRECT = {"salles": [{"salle": SALLE, "debut": T0 - 600, "participants": [
    {"sid": "PA_1", "participant": "gandalf", "compte": True, "depuis": T0 - 1440, "medias": {"son": True, "image": True, "ecran": False},
     "transport": "UDP", "appareil": "Linux · Firefox"},
    {"sid": "PA_2", "participant": "invité", "compte": False, "depuis": T0 - 1320, "medias": {"son": True, "image": False, "ecran": True},
     "transport": "TCP", "appareil": "iOS · Safari"}]}], "releve": T0}
HISTO = [{"sid": "PA_3", "salle": SALLE, "debut": T0 - 3600, "fin": T0 - 3000, "duree": 600, "participant": "gandalf", "compte": True,
          "appareil": "Linux · Firefox", "transport": "UDP", "pays": "FR", "issue": "aboutie", "motif": "a quitté"},
         {"sid": "PA_4", "salle": AUTRE, "debut": T0 - 4000, "fin": T0 - 4000, "duree": 0, "participant": "=HYPERLINK(\"x\")",
          "compte": False, "appareil": None, "transport": None, "pays": None, "issue": "echec", "motif": "aucun chemin média"}]
JOURS = [{"jour": f"2026-10-{j}", "abouties": 2 if j == 26 else 0, "echecs": 1 if j == 26 else 0} for j in range(20, 27)]
STATS = {"periode": 7, "sessions": 3, "sessions_abouties": 2, "echecs": 1, "secondes": 4320, "reunions": 1,
         "participants": {"comptes": 1, "invites": 1}, "mediane": 840, "pic": {"nombre": 2, "quand": T0},
         "transport": {"UDP": 2}, "motifs": {"a quitté": 1, "aucun chemin média": 1},
         "appareils": {"Linux · Firefox": 1, "iOS · Safari": 1}, "salles": {SALLE: 4320}, "par_jour": JOURS}
ROUTES = {**P.API, "/reunions": (200, REUNIONS), "/connexions": (200, {"en_direct": DIRECT, "historique": HISTO}),
          "/stats": (200, STATS)}


def ouvre(navigateur, routes=None, url="http://sbx.test/meet/", taille=None):
    ctx, p, erreurs, appels = P.ouvre(navigateur, url, routes or ROUTES, taille)
    p.urls = []
    p.on("request", lambda r: p.urls.append(r.url) if "/api/v1/meet/" in r.url else None)
    return ctx, p, erreurs, appels


def onglet(p, nom):
    p.click(f"[role=tab][data-t={nom}]")
    p.wait_for_timeout(300)


def test_trois_onglets_apres_le_tableau_de_bord(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    noms = p.eval_on_selector_all(".onglets [role=tab]", "bs => bs.map(b => b.dataset.t)")
    assert noms[:4] == ["tableau", "reunions", "connexions", "stats"] and not erreurs
    ctx.close()


def test_reunions_liste_lien_et_noms_en_texte(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    onglet(p, "reunions")
    lignes = p.locator("#lReunions tbody tr")
    assert lignes.count() == 2
    assert "EN COURS · 2" in lignes.nth(0).inner_text() and "gandalf" in lignes.nth(0).inner_text()
    assert lignes.nth(0).locator("a").get_attribute("href") == "//visio.example.org/gii-cbvo-lpe"
    assert PIEGE in lignes.nth(1).inner_text() and p.evaluate("window.piege") is None
    assert lignes.nth(0).locator("button.danger").count() == 1 and lignes.nth(1).locator("button.danger").count() == 0
    assert "confiance" in lignes.nth(1).inner_text()                          # trusted, dit en français
    assert p.inner_text("#tSalles") == "2" and p.inner_text("#tEnCours") == "1" and p.inner_text("#tPresents") == "2"
    assert not erreurs
    ctx.close()


def test_clore_demande_confirmation_puis_envoie(navigateur):
    ctx, p, erreurs, appels = ouvre(navigateur)
    onglet(p, "reunions")
    p.click("#lReunions tbody tr >> nth=0 >> button.danger")
    assert not p.locator("#conf").is_hidden() and "gii-cbvo-lpe" in p.inner_text("#confTexte")
    p.click("#confNon")
    assert not [a for a in appels if a[1] == "/clore"]
    p.click("#lReunions tbody tr >> nth=0 >> button.danger")
    p.click("#confOui")
    p.wait_for_timeout(300)
    envoi = [a for a in appels if a[1] == "/clore"]
    assert envoi and json.loads(envoi[0][2]) == {"salle": SALLE, "confirmer": "meet"}
    assert not p.dialogues and not erreurs
    ctx.close()


def test_connexions_direct_historique_et_filtre(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    onglet(p, "connexions")
    direct = p.inner_text("#lDirect")
    assert "gandalf" in direct and "invité" in direct and "iOS · Safari" in direct and "son · écran" in direct and "TCP" in direct
    histo = p.locator("#lHisto tbody tr")
    assert histo.count() == 2 and "gii-cbvo-lpe" in histo.nth(0).inner_text()           # nom de salle tiré des réunions
    assert "aucun chemin média" in histo.nth(1).inner_text() and "10 min" in histo.nth(0).inner_text()
    p.select_option("#fIssue", "echec")
    p.wait_for_timeout(300)
    assert any("/connexions?" in u and "issue=echec" in u for u in p.urls)
    assert not erreurs
    ctx.close()


def test_export_csv_neutralise_les_formules(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    onglet(p, "connexions")
    with p.expect_download() as tele:
        p.click("#exportCsv")
    texte = open(tele.value.path(), encoding="utf-8").read()
    lignes = texte.strip().splitlines()
    assert lignes[0].lstrip("﻿").startswith("Début;Durée;Participant;Salle;Appareil;Transport;Issue")
    assert len(lignes) == 3 and "'=HYPERLINK" in texte and ";=HYPERLINK" not in texte
    assert not erreurs
    ctx.close()


def test_statistiques_tuiles_et_periode(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur)
    onglet(p, "stats")
    assert p.inner_text("#sTemps") == "1 h 12" and p.inner_text("#sMediane") == "14 min" and p.inner_text("#sPic") == "2"
    assert p.inner_text("#sEchecs") == "1 / 3" and p.inner_text("#sParticipants") == "1 + 1"
    assert p.locator("#sJours .jour").count() == 7
    assert "gii-cbvo-lpe" in p.inner_text("#sSalles")
    p.click("[data-periode='30']")
    p.wait_for_timeout(300)
    assert any("/stats?periode=30" in u for u in p.urls)
    assert not erreurs
    ctx.close()


def test_sans_session_les_onglets_le_disent(navigateur):
    routes = {**ROUTES, "/reunions": (401, {}), "/connexions": (401, {}), "/stats": (401, {})}
    ctx, p, erreurs, _ = ouvre(navigateur, routes)
    for nom, boite in (("reunions", "#lReunions"), ("connexions", "#lDirect"), ("stats", "#sJours")):
        onglet(p, nom)
        assert "session requise" in p.inner_text(boite).lower()
    assert not erreurs
    ctx.close()


def test_demonstration_et_cloture_inerte(navigateur):
    ctx, p, erreurs, appels = ouvre(navigateur, url="http://sbx.test/meet/?demo=1")
    onglet(p, "reunions")
    assert p.locator("#lReunions tbody tr").count() >= 2
    p.click("#lReunions tbody tr >> nth=0 >> button.danger")
    p.click("#confOui")
    p.wait_for_timeout(200)
    assert not [a for a in appels if a[0] != "GET"]
    onglet(p, "stats")
    assert p.inner_text("#sTemps") != "—" and not erreurs
    ctx.close()


def test_telephone_sans_debordement_horizontal(navigateur):
    ctx, p, erreurs, _ = ouvre(navigateur, taille={"width": 390, "height": 844})
    for nom in ("reunions", "connexions", "stats"):
        onglet(p, nom)
        assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), nom
    assert not erreurs
    ctx.close()

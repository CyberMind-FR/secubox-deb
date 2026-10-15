# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2728 — la page du panneau maître liste les box détectées, les prépare sans code, et règle l'envoi automatique. API simulée, page réelle."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = (Path(__file__).resolve().parents[1] / "www" / "premier-pas-maitre" / "index.html").read_text(encoding="utf-8")
PROFIL = {"box": {"nom": "gk3", "fuseau": "Europe/Paris", "langue": "fr"}, "admin": {"mot_de_passe": "défini"}, "reseau": {"mode": "routeur", "domaine": "gk3.secubox.in"},
          "services": {"profil": "full"}, "maillage": {"mode": "plus_tard"}, "apt": {"auto": True, "heure": "03:00"}}
MAINTENANT = 1_800_000_000


def boxes():
    return [{"adresse": "192.168.1.9", "nom": "gk3", "etat": "nouvelle", "premiere_vue": MAINTENANT - 100, "derniere_vue": MAINTENANT - 30},
            {"adresse": "192.168.1.60", "nom": None, "etat": "preparee", "derniere_vue": MAINTENANT - 4000,
             "dernier": {"le": MAINTENANT - 50, "profil": "gk3", "mode": "remplir", "ok": True, "auto": True, "arret": None}},
            {"adresse": "192.168.1.61", "nom": "gk1", "etat": "configuree", "derniere_vue": MAINTENANT - 10}]


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, etat=None, taille=None, hostile=False, erreur_reglages=None):
    ctx = nav.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    cible = {"boxes": boxes(), "reglages": {"auto": False, "profil": "", "mode": "remplir"}} if etat is None else etat
    if hostile:
        cible["boxes"][0]["nom"] = "<img src=x onerror=window.pwn=1>"
        cible["boxes"][0]["dernier"] = {"le": 1, "profil": "<b>x</b>", "mode": "remplir", "ok": False, "auto": False, "arret": "<script>window.pwn=2</script>"}

    def api(r):
        u = r.request.url.split("/api/v1/premier-pas", 1)[1].split("?")[0]
        corps = r.request.post_data
        appels.append((r.request.method, u, json.loads(corps) if corps else None))
        j = {}
        if u == "/maitre/profils":
            j = {"profils": [{"nom": "gk3", "complet": True, "reprendre": "—", "erreurs": {}, "modifie": 1, "profil": PROFIL}]}
        elif u == "/maitre/profils/gk3":
            j = {"nom": "gk3", "profil": PROFIL}
        elif u in ("/maitre/decouverte", "/maitre/decouverte/analyser"):
            j = cible
        elif u == "/maitre/decouverte/preparer":
            j = {"ok": True, "faites": ["Nom", "Horloge"], "complet": True}
        elif u == "/maitre/decouverte/reglages":
            if erreur_reglages:
                r.fulfill(status=400, content_type="application/json", body=json.dumps({"detail": erreur_reglages}))
                return
            j = {"auto": True, "profil": "gk3", "mode": "remplir"}
        elif u == "/maitre/distant":
            r.fulfill(status=502, content_type="application/json", body=json.dumps({"detail": "injoignable"}))    # le suivi réessaie : le message d'envoi reste affiché
            return
        r.fulfill(status=200, content_type="application/json", body=json.dumps(j))
    p.route("**/api/v1/premier-pas/**", api)
    p.route("**/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://sbx.test/maitre/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.goto("http://sbx.test/maitre/")
    p.wait_for_selector("#boxes .det, #boxes .etat")
    return ctx, p, erreurs, appels


def test_les_box_detectees_sont_listees_avec_leur_etat_et_leur_dernier_envoi(nav):
    ctx, p, err, _ = ouvre(nav)
    assert p.locator("#boxes .det").count() == 3
    assert p.get_attribute('#boxes .det[data-adr="192.168.1.9"]', "class").endswith("nouvelle")
    t = p.inner_text("#boxes")
    assert "192.168.1.9" in t and "gk3" in t and "nouvelle" in t and "configurée" in t
    assert "dernier envoi : ✓ gk3 (remplir, automatique)" in t
    assert err == []
    ctx.close()


def test_une_box_configuree_n_a_pas_de_bouton_preparer(nav):
    ctx, p, _, _ = ouvre(nav)
    assert p.locator('#boxes .det[data-adr="192.168.1.61"] [data-act="preparer"]').count() == 0
    assert p.locator('#boxes .det[data-adr="192.168.1.9"] [data-act="preparer"]').count() == 1
    ctx.close()


def test_aucune_box_dit_clairement_qu_il_n_y_en_a_pas(nav):
    ctx, p, _, _ = ouvre(nav, {"boxes": [], "reglages": {"auto": False, "profil": "", "mode": "remplir"}})
    assert "Aucune box SecuBox détectée" in p.inner_text("#boxes")
    ctx.close()


def test_preparer_sans_profil_choisi_explique_quoi_faire(nav):
    ctx, p, _, appels = ouvre(nav)
    p.click('#boxes .det[data-adr="192.168.1.9"] [data-act="preparer"]')
    p.wait_for_selector("#toast.error", state="visible")
    assert "Choisissez d'abord un profil" in p.inner_text("#toast")
    assert not [a for a in appels if a[1] == "/maitre/decouverte/preparer"]
    ctx.close()


def test_preparer_envoie_le_profil_choisi_sans_code_ni_mot_de_passe(nav):
    ctx, p, err, appels = ouvre(nav)
    p.click('.ligne[data-n="gk3"]')
    p.wait_for_function("document.getElementById('f-nom').value === 'gk3'")
    p.select_option("#p-mode", "proposer")
    p.click('#boxes .det[data-adr="192.168.1.9"] [data-act="preparer"]')
    p.wait_for_function("document.getElementById('suivi').textContent.includes('étapes remplies')")
    envoi = [a for a in appels if a[1] == "/maitre/decouverte/preparer"][0]
    assert envoi[2] == {"adresse": "192.168.1.9", "nom": "gk3", "mode": "proposer"}
    assert "sans code" in p.inner_text("#suivi") and err == []
    ctx.close()


def test_le_champ_code_est_facultatif_dans_le_formulaire_manuel(nav):
    ctx, p, _, _ = ouvre(nav)
    assert "facultatif" in p.inner_text("label:has(#p-code)").lower() and p.get_attribute("#p-code", "required") is None
    ctx.close()


def test_oublier_une_box(nav):
    ctx, p, _, appels = ouvre(nav)
    p.click('#boxes .det[data-adr="192.168.1.9"] [data-act="oublier"]')
    p.wait_for_timeout(300)
    assert any(a[0] == "DELETE" and a[1] == "/maitre/decouverte/192.168.1.9" for a in appels)
    ctx.close()


def test_l_analyse_a_la_demande(nav):
    ctx, p, _, appels = ouvre(nav)
    n = len([a for a in appels if a[1] == "/maitre/decouverte/analyser"])
    p.click("#analyser")
    p.wait_for_timeout(400)
    assert len([a for a in appels if a[1] == "/maitre/decouverte/analyser"]) == n + 1
    ctx.close()


def test_l_envoi_automatique_envoie_le_profil_et_un_mode_non_forcer(nav):
    ctx, p, err, appels = ouvre(nav)
    p.click('.ligne[data-n="gk3"]')
    p.wait_for_function("document.getElementById('f-nom').value === 'gk3'")
    p.select_option("#p-mode", "forcer")                         # même « forcer » sélectionné : l'automatique reste « remplir »
    p.check("#auto")
    p.wait_for_timeout(400)
    r = [a for a in appels if a[0] == "PUT" and a[1] == "/maitre/decouverte/reglages"][0]
    assert r[2] == {"auto": True, "profil": "gk3", "mode": "remplir"} and err == []
    ctx.close()


def test_un_refus_des_reglages_decoche_la_case_et_le_dit(nav):
    ctx, p, _, _ = ouvre(nav, erreur_reglages="Ce profil est incomplet : reprendre à « Nom ».")
    p.check("#auto")
    p.wait_for_selector("#toast.error", state="visible")
    assert "incomplet" in p.inner_text("#toast") and not p.is_checked("#auto")
    ctx.close()


def test_l_etat_automatique_actif_est_annonce(nav):
    ctx, p, _, _ = ouvre(nav, {"boxes": boxes(), "reglages": {"auto": True, "profil": "gk3", "mode": "proposer"}})
    assert p.is_checked("#auto") and "Envoi automatique actif : profil « gk3 », mode proposer" in p.inner_text("#detNote")
    ctx.close()


def test_les_valeurs_hostiles_restent_du_texte(nav):
    ctx, p, err, _ = ouvre(nav, hostile=True)
    assert p.evaluate("window.pwn") is None and p.locator("#boxes img, #boxes b b, #boxes script").count() == 0
    assert "<img" in p.inner_text("#boxes") and err == []
    ctx.close()


@pytest.mark.parametrize("larg", [420, 800, 1300])
def test_pas_de_debordement(nav, larg):
    ctx, p, err, _ = ouvre(nav, taille={"width": larg, "height": 900})
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2745 — la page /users/ règle le second facteur PAR COMPTE : sélecteur, politique lisible, confirmation pour « désactivé » (avertissement pour un administrateur).

Vrai navigateur, API simulée. Réutilise le banc de test_users_aurora_2571."""
import json
from pathlib import Path

import pytest

from test_users_aurora_2571 import ROUTES, SRC, navigateur, ouvre  # noqa: F401

pytest.importorskip("playwright.sync_api")

COMPTES = {"users": [
    {"username": "admin", "email": "admin@example.org", "enabled": True, "role": "admin", "totp_enabled": True, "services": [], "created": "2026-05-02T09:12:00"},
    {"username": "jdupont", "email": "j@example.org", "enabled": True, "role": "viewer", "totp_enabled": False, "services": [], "created": "2026-08-19T14:30:00", "otp_mode": "toujours"},
    {"username": "ancien", "email": "a@example.org", "enabled": True, "role": "operator", "totp_enabled": True, "services": [], "created": "2026-08-19T14:30:00", "otp_mode": "jamais"},
    {"username": "hl", "email": "h@example.org", "enabled": True, "role": "operator", "totp_enabled": False, "services": [], "created": "2026-08-19T14:30:00", "otp_mode": "hors_lan"}], "total": 4}


def routes(reglage="facultatif", extra=None):
    r = dict(ROUTES)
    r[("GET", "/api/v1/users/users")] = (200, COMPTES)
    r[("GET", "/api/v1/auth/settings")] = (200, {"otp_lan": reglage, "otp_wan": "obligatoire", "require_admin_totp": reglage == "obligatoire"})
    r.update(extra or {})
    return r


def ouvrir(nav, **kw):
    ctx, p, err, appels = ouvre(nav, "http://sbx.test/users/", routes(**kw))
    p.wait_for_selector("#bComptes select[data-otp]", state="attached")
    return ctx, p, err, appels


def sel(p, nom):
    return p.locator(f'#bComptes select[data-otp="{nom}"]')


def mises_a_jour(appels):
    return [(m, c, json.loads(b) if b else None) for m, c, b in appels if c.endswith("/otp-mode")]


# ---------- statique ----------

def test_la_route_et_les_quatre_modes_sont_dans_la_page():
    assert "appel('PUT', API, '/user/' + encodeURIComponent(nom) + '/otp-mode'" in SRC
    for m in ("defaut", "hors_lan", "toujours", "jamais"):
        assert f"'{m}'" in SRC or f"{m}:" in SRC, m
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC


# ---------- le sélecteur ----------

def test_les_selecteurs_refletent_le_mode_de_chaque_compte(navigateur):
    ctx, p, err, _ = ouvrir(navigateur)
    assert [sel(p, n).input_value() for n in ("admin", "jdupont", "ancien", "hl")] == ["defaut", "toujours", "jamais", "hors_lan"]
    assert sel(p, "admin").locator("option").all_inner_texts() == ["Selon le réglage général", "Hors LAN seulement", "Toujours", "Désactivé"]
    assert err == []
    ctx.close()


def test_chaque_selecteur_nomme_son_compte_pour_les_lecteurs_d_ecran(navigateur):
    ctx, p, _, _ = ouvrir(navigateur)
    assert "admin" in sel(p, "admin").get_attribute("aria-label") and "second facteur" in sel(p, "admin").get_attribute("aria-label").lower()
    ctx.close()


def test_la_politique_effective_est_ecrite_en_clair(navigateur):
    ctx, p, _, _ = ouvrir(navigateur)
    ligne = lambda nom: p.locator(f'#bComptes tr:has(select[data-otp="{nom}"]) .otp-effet').inner_text()  # noqa: E731
    assert "hors du LAN" in ligne("admin") and "hors du LAN" in ligne("hl")
    assert "partout" in ligne("jdupont") and "Aucun code" in ligne("ancien") and "internet" in ligne("ancien")
    ctx.close()


def test_le_mode_par_defaut_suit_le_reglage_general(navigateur):
    ctx, p, _, _ = ouvrir(navigateur, reglage="obligatoire")
    assert "partout" in p.locator('#bComptes tr:has(select[data-otp="admin"]) .otp-effet').inner_text()
    ctx.close()


# ---------- changer le mode ----------

@pytest.mark.parametrize("mode", ["hors_lan", "toujours", "defaut"])
def test_un_mode_sans_risque_s_applique_tout_de_suite(navigateur, mode):
    ctx, p, err, appels = ouvrir(navigateur)
    sel(p, "ancien").select_option(mode)
    p.wait_for_timeout(400)
    assert mises_a_jour(appels) == [("PUT", "/api/v1/users/user/ancien/otp-mode", {"mode": mode})]
    assert p.locator("#conf").is_hidden() and err == []
    ctx.close()


def test_desactiver_demande_confirmation_avec_un_avertissement_pour_un_administrateur(navigateur):
    ctx, p, _, appels = ouvrir(navigateur)
    sel(p, "admin").select_option("jamais")
    p.wait_for_selector("#conf", state="visible")
    t = p.inner_text("#confTexte")
    assert "admin" in t and "administrateur" in t and "internet" in t and "mot de passe" in t
    assert mises_a_jour(appels) == [], "rien n'est envoyé avant la confirmation"
    ctx.close()


def test_confirmer_envoie_le_mode_avec_la_confirmation_explicite(navigateur):
    ctx, p, _, appels = ouvrir(navigateur)
    sel(p, "admin").select_option("jamais")
    p.wait_for_selector("#conf", state="visible")
    p.click("#confOui")
    p.wait_for_timeout(400)
    assert mises_a_jour(appels) == [("PUT", "/api/v1/users/user/admin/otp-mode", {"mode": "jamais", "confirmer": True})]
    ctx.close()


def test_annuler_remet_le_selecteur_et_n_envoie_rien(navigateur):
    ctx, p, _, appels = ouvre_et_change(navigateur)
    p.click("#confNon")
    assert sel(p, "admin").input_value() == "defaut" and mises_a_jour(appels) == []
    ctx.close()


def ouvre_et_change(navigateur):
    ctx, p, err, appels = ouvrir(navigateur)
    sel(p, "admin").select_option("jamais")
    p.wait_for_selector("#conf", state="visible")
    return ctx, p, err, appels


def test_un_utilisateur_ordinaire_est_aussi_confirme_mais_sans_le_texte_administrateur(navigateur):
    ctx, p, _, _ = ouvrir(navigateur)
    sel(p, "hl").select_option("jamais")
    p.wait_for_selector("#conf", state="visible")
    t = p.inner_text("#confTexte")
    assert "hl" in t and "administrateur" not in t
    ctx.close()


def test_un_refus_de_l_api_remet_le_selecteur_et_dit_pourquoi(navigateur):
    refus = {("PUT", "/api/v1/users/user/ancien/otp-mode"): (400, {"detail": "Mode du second facteur : defaut, hors_lan, toujours ou jamais."})}
    ctx, p, _, _ = ouvre_avec(navigateur, refus)
    sel(p, "ancien").select_option("hors_lan")
    p.wait_for_selector("#rComptes.ko", state="visible")
    assert "Mode du second facteur" in p.inner_text("#rComptes") and sel(p, "ancien").input_value() == "jamais"
    ctx.close()


def ouvre_avec(navigateur, extra):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/users/", routes(extra=extra))
    p.wait_for_selector("#bComptes select[data-otp]", state="attached")
    return ctx, p, err, appels


def test_succes_message_et_rechargement_de_la_liste(navigateur):
    ctx, p, _, appels = ouvrir(navigateur)
    n = len([a for a in appels if a[1].endswith("/api/v1/users/users")])
    sel(p, "ancien").select_option("toujours")
    p.wait_for_selector("#rComptes.ok", state="visible")
    assert "ancien" in p.inner_text("#rComptes")
    assert len([a for a in appels if a[1].endswith("/api/v1/users/users")]) == n + 1
    ctx.close()


def test_en_demonstration_l_action_est_inerte_et_le_dit(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/?demo=1", routes())
    p.wait_for_selector("#bComptes select[data-otp]", state="attached")
    s = p.locator("#bComptes select[data-otp]").first
    nom = s.get_attribute("data-otp")
    s.select_option("hors_lan")
    p.wait_for_selector("#rComptes.ko", state="visible")
    assert "Démonstration" in p.inner_text("#rComptes") and mises_a_jour(appels) == []
    ctx.close()


def test_un_nom_hostile_reste_du_texte(navigateur):
    mal = {"users": [{"username": "<img src=x onerror=window.pwn=1>", "email": "", "enabled": True, "role": "viewer", "totp_enabled": False, "services": [], "created": "2026-05-02T09:12:00"}], "total": 1}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/users/", routes(extra={("GET", "/api/v1/users/users"): (200, mal)}))
    p.wait_for_selector("#bComptes select[data-otp]", state="attached")
    assert p.evaluate("window.pwn") is None and p.locator("#bComptes img").count() == 0 and err == []
    ctx.close()


@pytest.mark.parametrize("larg", [420, 800, 1300])
def test_pas_de_debordement(navigateur, larg):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/users/", routes(), {"width": larg, "height": 900})
    p.wait_for_selector("#bComptes select[data-otp]", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()

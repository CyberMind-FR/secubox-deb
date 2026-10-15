# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2761 — /identite/ (Administration) : le panneau « Comptes » d'une personne montre PhotoPrism, ouvert par SSO (OIDC, #2255).

Pas de mot de passe, pas de création ni de lien à poser : le compte naît à la première connexion avec le pseudo de la personne."""
from test_identite_modifier_lien_2755 import UID, navigateur, ouvre  # noqa: F401


def ligne(p):
    return p.locator("tr.cpt .svc", has_text="PhotoPrism")


def test_photoprism_figure_dans_les_comptes_d_une_personne(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        assert ligne(p).count() == 1
        txt = ligne(p).inner_text()
        assert "SSO" in txt and "ana" in txt, txt
    finally:
        ctx.close()


def test_la_ligne_est_informative_rien_a_ouvrir_ni_a_relier(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        assert ligne(p).locator("button, input").count() == 0
    finally:
        ctx.close()


def test_l_identifiant_est_le_pseudo_de_la_personne_pas_un_nom_invente(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        assert p.locator("tr.cpt .svc .mono", has_text="ana").count() >= 1
        assert ligne(p).locator(".mono").inner_text().strip() == "ana"
    finally:
        ctx.close()


def test_les_autres_services_sont_inchanges(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        assert p.locator("tr.cpt .svc", has_text="Courriel").count() == 1
        assert p.locator("tr.cpt .svc", has_text="Nextcloud").count() == 1
        assert p.locator("tr.cpt .svc").count() == 3
    finally:
        ctx.close()


def test_l_explication_dit_comment_le_compte_naît(navigateur):
    ctx, p, _ = ouvre(navigateur)
    try:
        t = ligne(p).inner_text().lower()
        assert "première connexion" in t or "premiere connexion" in t
    finally:
        ctx.close()

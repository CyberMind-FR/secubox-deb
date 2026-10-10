# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2255 : `photoprismctl install` configure l'entrée OIDC une fois PhotoPrism installé. Le postinst la rejouait trop tôt (« PhotoPrism pas encore
installé ; sso reporté ») et personne ne la rejouait ensuite : PhotoPrism restait sans SSO."""
from pathlib import Path

CTL = (Path(__file__).resolve().parents[1] / "sbin" / "photoprismctl").read_text()


def corps(nom):
    debut = CTL.index(f"{nom}() {{")
    return CTL[debut:CTL.index("\n}\n", debut)]


def test_install_appelle_sso_apres_l_amorcage_reussi():
    c = corps("cmd_install")
    assert "bash \"$INSTALL_LIB\" || {" in c and "cmd_sso" in c
    assert c.index("cmd_sso") > c.index('bash "$INSTALL_LIB"'), "sso doit suivre l'installation, pas la précéder"


def test_un_echec_de_sso_n_annule_pas_l_installation():
    assert "cmd_sso ||" in corps("cmd_install")        # prévient, ne sort pas en erreur


def test_sso_reporte_encore_si_photoprism_n_est_pas_installe():
    assert "sso reporté" in corps("cmd_sso")

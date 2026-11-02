# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : le bandeau santé partagé affiche un bandeau rouge persistant tant que le mot de passe par défaut est actif."""
from pathlib import Path

JS = (Path(__file__).resolve().parents[1] / "www" / "shared" / "health-banner.js").read_text()


def test_interroge_l_indicateur_unique():
    assert "'/api/v1/auth/mot-de-passe-defaut'" in JS
    assert "checkDefaultPassword();" in JS and "setInterval(checkDefaultPassword" in JS


def test_bandeau_rouge_persistant_sans_bouton_fermer_et_lien():
    i = JS.index("function defaultPasswordStrip")
    bloc = JS[i:JS.index("async function checkDefaultPassword")]
    assert "role', 'alert'" in bloc and "#b00020" in bloc and "Changer le mot de passe" in bloc
    assert "close" not in bloc.lower() and "fermer" not in bloc.lower()
    # Aucune injection HTML : textContent seulement, lien relatif seulement.
    assert "innerHTML" not in bloc and "startsWith('/')" in bloc


def test_disparait_quand_le_defaut_est_leve():
    assert "etat.actif !== true" in JS and "el.remove()" in JS

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""rapport.resume_statuts : résumé EMOJI des codes de retour (#1131an).

Le PDF est en latin-1 (pas d'emoji) ; le résumé emoji va dans le CORPS du mail
(UTF-8). On vérifie le groupement par classe et les émoticônes par type d'erreur.
"""
import rapport


def test_vide_rend_chaine_vide():
    assert rapport.resume_statuts(None) == ""
    assert rapport.resume_statuts({}) == ""


def test_groupe_par_classe_avec_emoji():
    """Chaque classe présente est étiquetée par son emoji de classe."""
    resume = rapport.resume_statuts({"200": 90, "301": 5, "404": 4, "500": 1})
    assert "🟢 2xx" in resume
    assert "🔵 3xx" in resume
    assert "🟠 4xx" in resume
    assert "🔴 5xx" in resume


def test_codes_erreur_ont_emoji_par_type():
    """Les 4xx/5xx détaillent les codes avec l'émoticône de LEUR type."""
    resume = rapport.resume_statuts({"404": 12, "403": 3, "502": 7})
    assert "🔍 404" in resume   # not found
    assert "🚫 403" in resume   # forbidden
    assert "🔌 502" in resume   # bad gateway


def test_classe_absente_omise():
    """Aucune classe 3xx → pas de ligne 3xx (on n'affiche pas de zéro)."""
    resume = rapport.resume_statuts({"200": 10, "404": 2})
    assert "3xx" not in resume
    assert "5xx" not in resume


def test_ne_detaille_pas_les_2xx_3xx():
    """Le détail par code ne concerne que les erreurs (4xx/5xx)."""
    resume = rapport.resume_statuts({"200": 10, "301": 5})
    # Ligne de classe présente, mais pas de détail « · code:n » pour 2xx/3xx.
    assert "🟢 2xx" in resume
    assert " · " not in resume


def test_code_erreur_inconnu_a_emoji_generique():
    """Un code d'erreur hors table (ex. 418) reste listé, avec ⚠️ générique."""
    resume = rapport.resume_statuts({"418": 4})
    assert "⚠️ 418" in resume

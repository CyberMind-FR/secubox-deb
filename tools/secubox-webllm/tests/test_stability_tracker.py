# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: tests.test_stability_tracker — le détecteur de fin de
génération, en logique pure (sans page, sans réseau, sans async).
"""

from __future__ import annotations

import pytest

from webllm.session import StabilityTracker


def test_growing_text_never_completes():
    """Un texte qui grossit à chaque lecture (streaming) ne se stabilise jamais."""
    tracker = StabilityTracker(stability_polls=3)
    chunks = ["Bon", "Bonj", "Bonjo", "Bonjou", "Bonjour"]
    results = [tracker.observe(chunk, stop_visible=False) for chunk in chunks]
    assert not any(results)


def test_stable_text_but_stop_button_visible_never_completes():
    """Texte identique mais bouton stop toujours visible : le streaming continue."""
    tracker = StabilityTracker(stability_polls=3)
    results = [tracker.observe("Bonjour", stop_visible=True) for _ in range(10)]
    assert not any(results)


def test_completes_after_required_consecutive_stable_polls():
    """La complétion n'arrive qu'après `stability_polls` CONFIRMATIONS, pas avant.

    La toute première apparition d'un texte ne peut pas, à elle seule,
    prouver une stabilité (rien à comparer) : elle initialise le compteur
    sans le faire progresser. Il faut donc `stability_polls` lectures
    identiques supplémentaires après cette apparition.
    """
    tracker = StabilityTracker(stability_polls=3)
    assert (
        tracker.observe("Bonjour", stop_visible=False) is False
    )  # apparition initiale
    assert tracker.observe("Bonjour", stop_visible=False) is False  # confirmation 1
    assert tracker.observe("Bonjour", stop_visible=False) is False  # confirmation 2
    assert (
        tracker.observe("Bonjour", stop_visible=False) is True
    )  # confirmation 3 → complet


def test_stop_button_reappearing_resets_the_counter():
    """Une réapparition du bouton stop après un début de stabilité repart de zéro."""
    tracker = StabilityTracker(stability_polls=2)
    assert tracker.observe("Bonjour", stop_visible=False) is False
    assert tracker.observe("Bonjour", stop_visible=True) is False  # reset : stop reparu
    assert tracker.observe("Bonjour", stop_visible=False) is False  # recompte 1
    assert tracker.observe("Bonjour", stop_visible=False) is True  # 2 → complet


def test_text_change_after_partial_stability_resets_the_counter():
    """Un nouveau chunk de texte après un début de stabilité repart de zéro."""
    tracker = StabilityTracker(stability_polls=2)
    assert tracker.observe("Bonjour", stop_visible=False) is False
    assert tracker.observe("Bonjour tou", stop_visible=False) is False  # texte a changé
    assert tracker.observe("Bonjour tou", stop_visible=False) is False
    assert tracker.observe("Bonjour tou", stop_visible=False) is True


def test_empty_response_can_be_reported_stable_by_the_tracker():
    """Le tracker seul ne juge pas du contenu : une chaîne vide stable est signalée
    complète (c'est à l'appelant — `wait_stable` — de refuser une réponse vide)."""
    tracker = StabilityTracker(stability_polls=2)
    assert tracker.observe("", stop_visible=False) is False  # apparition initiale
    assert tracker.observe("", stop_visible=False) is False  # confirmation 1
    assert tracker.observe("", stop_visible=False) is True  # confirmation 2 → complet


def test_invalid_stability_polls_rejected():
    """`stability_polls` doit être strictement positif."""
    with pytest.raises(ValueError):
        StabilityTracker(stability_polls=0)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Empreintes courtes et identifiants dérivés."""
import pytest

from secubox_core.crypto.empreinte import empreinte, ident, jeton


def test_stable_entre_deux_appels():
    """Un identifiant d'enregistrement DOIT être reproductible : c'est ce qui
    permet de le recalculer après redémarrage."""
    assert ident("https://exemple.fr/hook") == ident("https://exemple.fr/hook")


def test_parties_separees_sans_ambiguite():
    """Le piège classique de la concaténation : deux découpages différents ne
    doivent pas donner le même identifiant."""
    assert ident("ab", "c") != ident("a", "bc")
    assert ident("a", "b") != ident("ab")


def test_liaison_de_domaine():
    assert ident("x", domaine="webhook") != ident("x", domaine="politique")


@pytest.mark.parametrize("n", [6, 8, 12, 32, 64])
def test_longueurs_admises(n):
    assert len(ident("x", n=n)) == n


@pytest.mark.parametrize("n", [0, 1, 5, 65, 128])
def test_longueurs_refusees(n):
    """Refuser à l'appel plutôt que de découvrir les collisions en production."""
    with pytest.raises(ValueError):
        ident("x", n=n)


def test_accepte_les_types_courants_sans_planter():
    assert len(ident("texte", b"octets", 42, None)) == 12


def test_empreinte_est_bien_du_sha256():
    import hashlib
    attendu = hashlib.sha256(b"seul").hexdigest()
    assert empreinte("seul") == attendu          # une partie, aucun séparateur
    assert len(empreinte("a", "b")) == 64


def test_jeton_est_imprevisible_et_non_derive():
    """`jeton` et `ident` ne doivent JAMAIS être confondus : l'un est
    reconstructible par qui connaît l'entrée, l'autre non."""
    assert jeton() != jeton()
    assert len(jeton(32)) == 64
    with pytest.raises(ValueError):
        jeton(8)

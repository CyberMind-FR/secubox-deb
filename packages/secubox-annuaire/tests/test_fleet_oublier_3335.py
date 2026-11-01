# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3335 : bouton « Oublier » des pairs de la Flotte (nom retapé, seconde confirmation pour un nœud actif)."""
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "www" / "fleet" / "index.html").read_text(encoding="utf-8")


def test_bouton_oublier_et_routes():
    i = PAGE.index("function oublierNoeud(")
    bloc = PAGE[i:i + 3000]
    assert "/api/v1/p2p/master-link/oublier" in bloc
    # #3362 : UN seul point d'entrée (secubox-p2p enchaîne tous les nettoyages, Flotte du pilotage comprise) ; la page n'appelle
    # plus le pilotage elle-même (elle oubliait la box homonyme quand une ancienne clé était désignée) et montre ce qui reste.
    assert "/api/v1/pilotage/boxes/" not in bloc
    assert "d.restes" in bloc and "partiel" in bloc
    # correction #3362 : 202 + opération suivie par GET jusqu'à « termine » (plus de 504 trompeur)
    assert "/api/v1/p2p/master-link/oublier/' + encodeURIComponent(" in bloc and "'termine'" in bloc and "operation" in bloc
    assert "saisie.value !== nom" in bloc                                 # nom retapé, sinon rien n'est envoyé
    assert "forcer.checked" in bloc and "force: true" in bloc            # nœud encore en ligne : « forcer » coché
    assert "oublierNoeud(p.name, act, p.public_key)" in PAGE and "public_key: cle" in bloc and "<th>Dernier vu</th><th></th>" in PAGE


def test_le_bouton_n_est_pose_que_pour_un_nom_valide():
    assert "/^[a-z0-9][a-z0-9-]{0,62}$/.test(p.name)" in PAGE


def test_bouton_reactive_si_le_suivi_echoue():
    """#3362 passe 2 : un suivi en échec ne laisse pas le bouton désactivé."""
    i = PAGE.index("Suivi de l\\'oubli impossible")
    assert "ok.disabled = false" in PAGE[i:i + 120]


def test_confirmation_tient_dans_la_ligne():
    """Sur gk2 (2026-11-01), le champ de confirmation prenait toute la ligne et poussait « Oublier <nom> » hors de l'écran."""
    i = PAGE.index("function oublierNoeud(")
    corps = PAGE[i:PAGE.index("td.append", i) + 200] if "td.append" in PAGE[i:] else PAGE[i:]
    assert "el('div', 'oubli-conf')" in corps and "td.append(saisie" not in corps
    assert ".oubli-conf{display:flex;flex-wrap:wrap" in PAGE and ".oubli-conf input[type=text]{flex:0 1 160px;width:160px}" in PAGE


def test_pas_de_rafraichissement_pendant_la_confirmation():
    """Sur gk2 (2026-11-01), le rafraîchissement périodique redessinait les pairs et effaçait le nom en cours de saisie."""
    i = PAGE.index("async function chargerP2p(")
    assert PAGE[i:i + 200].count("if (!force && confirmationOuverte('p2p-body')) return;") == 1
    assert "non.addEventListener('click', () => chargerP2p(true));" in PAGE

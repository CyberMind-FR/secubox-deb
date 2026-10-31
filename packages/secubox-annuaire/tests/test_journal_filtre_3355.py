# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3355 — la voie rapide (20 s) ne décode plus tout le journal : filtre par opération dans SQLite, couples (auteur, signature) sans JSON."""
from annuaire.model import Op
from annuaire.verbs import _get_nodes, _seen_author_sig

from test_assist_sync_2540 import _signe, journal  # noqa: F401 — fixture partagée


def test_filtre_sql_par_prefixe(journal):  # noqa: F811
    assert [e.op for e in journal.iter_entries(("ban_",))] == [Op.BAN_PUBLISH] * 6
    assert {e.op for e in journal.iter_entries(("assist_", "invite_"))} == {Op.ASSIST_OFFER, Op.ASSIST_REQUEST_OPEN, Op.INVITE_ACCEPT}
    assert len(list(journal.iter_entries())) == 9


def test_filtre_garde_l_ordre_des_hauteurs(journal):  # noqa: F811
    h = [e.height for e in journal.iter_entries(("ban_", "assist_"))]
    assert h == sorted(h)


def test_couples_auteur_signature_identiques_au_parcours_complet(journal):  # noqa: F811
    assert _seen_author_sig(journal) == {(e.author, e.sig) for e in journal.iter_entries()}


def test_fiches_de_noeud_seules_lues(journal):  # noqa: F811
    _signe(journal, Op.NODE_PUBLISH, {"did": "x"})
    assert _get_nodes(journal) == []                     # auteur ≠ did : écartée, comme avant

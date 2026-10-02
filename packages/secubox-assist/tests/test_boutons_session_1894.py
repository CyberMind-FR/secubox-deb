# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Les boutons de session ne sont plus muets (#1894) : message sans session, réponse lue."""
from pathlib import Path

PAGE = (Path(__file__).parent.parent / "www" / "assist" / "index.html").read_text()


def test_sans_session_un_message_pas_un_return_muet():
    assert "Aucune session d'assistance active" in PAGE
    assert "if (!sid) return;" not in PAGE


def test_reponse_du_post_examinee():
    # postAction affiche succès et échec ; l'ancien fetch nu les avalait.
    assert "await postAction(ep, corps, ok)" in PAGE
    assert "await fetch(ep, {method:'POST'" not in PAGE


def test_boutons_desactives_sans_session():
    assert "b.disabled = !d.active_session" in PAGE

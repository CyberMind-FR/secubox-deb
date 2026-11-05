# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3467 : un apply en ligne de commande enregistre le profil actif, que le hub lit pour masquer le menu."""
from api import cli


def test_noter_profil_actif(tmp_path):
    (tmp_path / "profiles").mkdir()
    cli.noter_profil_actif(tmp_path, "mobile")
    assert (tmp_path / "profiles/active").read_text() == "mobile\n"
    assert cli._active_profile_name(tmp_path, None) == "mobile"

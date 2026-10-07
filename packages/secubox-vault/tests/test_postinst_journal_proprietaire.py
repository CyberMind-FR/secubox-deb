# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le journal d'audit du coffre appartient au compte du service, même quand il existait déjà : sinon le coffre ne peut plus
s'ouvrir (« Permission denied » sur coffre.journal, constaté sur gk2 le 2026-10-07)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
POSTINST = (PKG / "debian" / "postinst").read_text()
UNITE = next((PKG / "debian").glob("secubox-vault.service")).read_text()


def test_le_service_ecrit_le_journal_sous_son_propre_compte():
    assert "User=secubox-coffre" in UNITE
    assert "/var/log/secubox/coffre.journal" in UNITE        # ReadWritePaths


def test_un_journal_existant_est_remis_au_compte_du_service_sans_toucher_son_contenu():
    assert "chown secubox-coffre:secubox /var/log/secubox/coffre.journal" in POSTINST
    assert "chmod 0640 /var/log/secubox/coffre.journal" in POSTINST
    # jamais de troncature ni de réécriture du journal chaîné
    for interdit in (": > /var/log/secubox/coffre.journal", "> /var/log/secubox/coffre.journal\n", "rm -f /var/log/secubox/coffre.journal"):
        assert interdit not in POSTINST.replace("install -o secubox-coffre -g secubox -m 0640 /dev/null /var/log/secubox/coffre.journal", "")


def test_la_correction_vient_apres_la_creation_et_dans_configure():
    i_creation = POSTINST.index("install -o secubox-coffre -g secubox -m 0640 /dev/null")
    i_chown = POSTINST.index("chown secubox-coffre:secubox /var/log/secubox/coffre.journal")
    assert i_creation < i_chown
    assert POSTINST.index("configure)") < i_chown < POSTINST.index(";;", i_chown)

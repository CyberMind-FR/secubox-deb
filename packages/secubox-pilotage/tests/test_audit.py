# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""R31 : le profil AppArmor n'accorde que `a` (ajout seul) sur audit.log ; le noyau exige la permission de création dès O_CREAT, même sur un
fichier existant : l'audit ne doit donc pas ouvrir avec O_CREAT (le journal est garanti par secubox-core et le postinst)."""
import inspect
import json

import pytest

from pilotage import audit as A


def test_audit_n_utilise_pas_o_creat():
    code = "\n".join(x.split("#")[0] for x in inspect.getsource(A).splitlines())
    assert "O_CREAT" not in code and "O_APPEND" in code and "O_NOFOLLOW" in code


def test_audit_ajoute_a_un_journal_existant(tmp_path):
    f = tmp_path / "audit.log"
    f.write_text("ligne existante\n")
    A.journal(f)("pilotage_releve_demande", {"cle": "maillage:gk5", "duree_s": 60})
    lignes = f.read_text().splitlines()
    assert lignes[0] == "ligne existante" and json.loads(lignes[1])["action"] == "pilotage_releve_demande"


def test_audit_journal_absent_erreur_claire_et_rien_cree(tmp_path):
    f = tmp_path / "audit.log"
    with pytest.raises(FileNotFoundError):
        A.journal(f)("x", {})
    assert not f.exists()

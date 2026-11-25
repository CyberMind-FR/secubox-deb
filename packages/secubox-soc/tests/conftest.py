# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Isolation commune des suites de secubox-soc (#3723).

`defense_etat.publier_mode()` écrit `/run/secubox/sade-mode.json` après chaque changement de mode ou de liste
blanche : aucun test ne doit écrire ce fichier sur le poste qui lance la suite (un `/run/secubox` réel le lirait).
"""
import os
import tempfile

import pytest

# AVANT tout import de `api.main`, qui lit cette variable une fois (#3946) : aucune suite ne doit toucher l'état SOC
# du poste qui la lance, ni dépendre de son existence. Le dossier disparaît avec le processus.
_ETAT = tempfile.TemporaryDirectory(prefix="soc-tests-")
os.environ["SECUBOX_SOC_DATA"] = _ETAT.name


@pytest.fixture(autouse=True)
def _fichier_sade_isole(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_SADE_MODE", str(tmp_path / "sade-mode.json"))

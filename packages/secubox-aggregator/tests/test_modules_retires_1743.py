# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Les modules retirés (docker/podman, #1743) cités dans aggregator.toml sont ignorés sans erreur."""
import importlib

import pytest

ag = importlib.import_module("aggregator.main")


def test_modules_retires_ignores_sans_erreur_de_chargement(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "hexo", "ollama", "frigate", "waf", "voip"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    cfg = ag._load_config()
    assert cfg["modules"] == ["hub", "waf"]                  # les vivants restent, dans l'ordre
    assert not ag._LOAD_ERRORS.get("hexo")                   # et aucune erreur par module disparu


def test_la_liste_des_retires_est_celle_du_retrait():
    assert ag.RETIRED_MODULES == {"hexo", "ollama", "gotosocial", "redroid", "simplex", "newsbin", "voip", "frigate"}


def test_aucun_module_vivant_n_est_marque_retire():
    for vivant in ("hub", "matrix", "jitsi", "photoprism", "voicestudio", "nac"):
        assert vivant not in ag.RETIRED_MODULES

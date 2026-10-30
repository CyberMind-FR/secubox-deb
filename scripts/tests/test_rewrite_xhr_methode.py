# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""rewrite-xhr.py : une méthode RPCD qui agit part en POST, une lecture en GET (#3126, L5).

Une action nommée sans suffixe (« restart », « stop », « start », « reload ») partait en GET :
une portée « lecture » (méthodes GET seulement) pouvait alors relancer un service.
"""
import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "rewrite-xhr.py"
_spec = importlib.util.spec_from_file_location("rewrite_xhr", _SCRIPT)
rewrite_xhr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rewrite_xhr)


@pytest.mark.parametrize("nom", ["restart", "stop", "start", "reload", "restart_service", "stop_all", "set_config"])
def test_action_part_en_post(nom):
    assert rewrite_xhr.methode_http(nom) == "POST"


@pytest.mark.parametrize("nom", ["status", "get_config", "stats", "list_rules", "startup_info_get"])
def test_lecture_part_en_get(nom):
    assert rewrite_xhr.methode_http(nom) == "GET"

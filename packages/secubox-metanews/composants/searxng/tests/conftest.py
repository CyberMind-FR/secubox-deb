# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests du composant searxng (#3581), hors réseau. L'API et searxngctl sont chargés par chemin, sous des noms propres :
jamais `api` dans sys.modules (collision avec les autres composants, cf. pytest.ini)."""
import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest

COMPOSANT = Path(__file__).resolve().parents[1]
if str(COMPOSANT) not in sys.path:
    sys.path.insert(0, str(COMPOSANT))


def charger_ctl():
    if "searxngctl_teste" in sys.modules:
        return sys.modules["searxngctl_teste"]
    chargeur = importlib.machinery.SourceFileLoader("searxngctl_teste", str(COMPOSANT / "sbin" / "searxngctl"))
    spec = importlib.util.spec_from_loader("searxngctl_teste", chargeur)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["searxngctl_teste"] = mod
    chargeur.exec_module(mod)
    return mod


def charger_api():
    if "searxng_api_teste" in sys.modules:
        return sys.modules["searxng_api_teste"]
    spec = importlib.util.spec_from_file_location("searxng_api_teste", COMPOSANT / "api" / "main.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["searxng_api_teste"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ctl():
    return charger_ctl()


@pytest.fixture
def api_mod():
    return charger_api()


@pytest.fixture
def cfg():
    from sbx_searxng import config as C

    return C.charger(COMPOSANT / "conf" / "searxng.toml.example")

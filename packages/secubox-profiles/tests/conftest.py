# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path

# Rend `api` importable en top-level (miroir du layout runtime sous
# /usr/lib/secubox/profiles), comme le conftest de secubox-billets.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _cgroup_neutre(tmp_path, monkeypatch):
    """Isole les tests du /sys/fs/cgroup de la machine (#1795) : par défaut, une
    racine SANS cgroup.controllers — le repli cgroup rend None, comme avant."""
    from api import observe
    racine = tmp_path / "cgroup-neutre"
    racine.mkdir()
    monkeypatch.setattr(observe, "CGROUP_ROOT", racine)
    return racine

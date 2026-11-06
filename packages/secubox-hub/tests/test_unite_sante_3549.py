# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Une page servie par un autre module reprend son état (#3549)."""
from pathlib import Path

S = (Path(__file__).resolve().parents[1] / "api/main.py").read_text(encoding="utf-8")


def test_le_releve_reprend_l_etat_de_l_unite():
    i = S.index('item.get("unite")', S.index("def _refresh_health_batch"))
    assert i < S.index('_cache["health_batch"] = {"modules"')
    assert "ident not in modules and unite in modules" in S

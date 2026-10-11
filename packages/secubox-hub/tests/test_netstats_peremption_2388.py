# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2388 — le seuil de péremption des stats réseau suit la cadence du collecteur (sinon « collecteur arrêté » en permanence)."""
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(RACINE / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _cadence():
    t = (RACINE / "packages/secubox-core/systemd/cadence/secubox-netstats.timer.conf").read_text(encoding="utf-8")
    periode = int(re.search(r"^OnUnitActiveSec=(\d+)s", t, re.M).group(1))
    alea = int(re.search(r"^RandomizedDelaySec=(\d+)s", t, re.M).group(1))
    return periode, alea


def test_le_seuil_depasse_une_periode_plus_le_delai_aleatoire_avec_marge():
    from api import netstats
    periode, alea = _cadence()
    assert netstats.STALE_AFTER_S >= 2 * (periode + alea) + 30, (netstats.STALE_AFTER_S, periode, alea)

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""#4034 : /categories en double tampon, dernier relevé servi aussitôt."""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import modes as M  # noqa: E402


def test_dernier_releve_servi_pendant_le_recalcul(monkeypatch):
    lent = threading.Event()
    appels = []

    def lire():
        appels.append(1)
        if len(appels) > 1:
            lent.wait(2)
        return {"categories": {"x": {"mode": "detect"}}, "total_rules": len(appels), "source": "box"}
    monkeypatch.setattr(M, "lire_categories", lire)
    M._invalider_categories()
    assert M.categories_tampon()["total_rules"] == 1
    monkeypatch.setattr(M, "CAT_FRAIS", 0.0)
    t0 = time.monotonic()
    r = M.categories_tampon()
    assert time.monotonic() - t0 < 0.5 and r["total_rules"] == 1      # pas d'attente du recalcul
    lent.set()
    time.sleep(0.2)
    assert M.categories_tampon()["total_rules"] == 2


def test_repli_paquet_n_ecrase_pas_la_box(monkeypatch):
    M._invalider_categories()
    monkeypatch.setattr(M, "lire_categories", lambda: {"categories": {}, "total_rules": 9, "source": "box"})
    M.categories_tampon()
    monkeypatch.setattr(M, "lire_categories", lambda: {"categories": {}, "total_rules": 0, "source": "paquet"})
    M._recalculer_categories()
    assert M.categories_tampon()["total_rules"] == 9

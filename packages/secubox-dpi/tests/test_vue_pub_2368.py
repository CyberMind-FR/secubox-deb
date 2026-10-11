# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2368 — la vue DPI lit les lectures agrégées (/pub/) : sur l'hôte admin /stats est une route legacy retirée, sans `connected`."""
import pathlib

V = (pathlib.Path(__file__).resolve().parents[1] / "www/dpi/vue.html").read_text(encoding="utf-8")


def test_les_six_lectures_passent_par_pub_avec_repli():
    assert "jget(b+'pub/'+n)" in V and "jget(b+n)" in V
    for n in ("stats", "usage", "countries", "clients", "suggestions", "sessions"):
        assert f"lis('{n}')" in V, n
    assert "jget(b+'stats')" not in V          # l'appel direct d'origine, qui donnait « HORS LIGNE »

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3728 : les leurres de service tiennent la conversation (régime bannière) pour capter les identifiants."""
from pathlib import Path

UNITE = (Path(__file__).resolve().parents[1] / "debian" / "secubox-authwatch.service").read_text(encoding="utf-8")


def test_regime_banniere_arme_avec_les_leurres():
    commande = UNITE.split("ExecStart=", 1)[1].split("Restart=", 1)[0]
    assert "--leurres defaut" in commande and "--leurre-bannieres" in commande

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2895 — sur la carte 1 Go, unbound-checkconf lit 119 553 domaines + la liste webfilter (22 Mo)
et depasse 60 s : la synchronisation echouait, unbound n'etait jamais recharge, le puits restait INACTIF.

Depuis #3205, la vérification est faite par secubox-dns-listes (secubox_unbound) : c'est son délai qui doit rester large,
et le script de synchronisation n'en lance plus aucune."""
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ICI.parents[1] / "common"))
import secubox_unbound as U  # noqa: E402

SRC = (ICI / "sbin" / "secubox-adblock-sync").read_text()


def test_le_delai_de_verification_est_large_pour_une_petite_carte():
    assert U.DELAI_CHECKCONF >= 300 and "unbound-checkconf" not in SRC

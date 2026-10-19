# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2895 — sur la carte 1 Go, unbound-checkconf lit 119 553 domaines + la liste webfilter (22 Mo)
et depasse 60 s : la synchronisation echouait, unbound n'etait jamais recharge, le puits restait INACTIF."""
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-adblock-sync").read_text()


def test_le_delai_de_verification_est_large_pour_une_petite_carte():
    m = re.search(r'unbound-checkconf", str\(UNBOUND_CONF\)\], (\d+)\)', SRC)
    assert m and int(m.group(1)) >= 300

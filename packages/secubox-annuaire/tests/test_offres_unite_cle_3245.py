# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3245 — secubox-annuaire-offres.service sautée proprement tant que la clé du nœud n'existe pas.

Au premier démarrage, la minuterie lançait l'unité avant `annuairectl init` : « no node key at
/etc/secubox/secrets/annuaire/node.key » et l'unité en échec. ConditionPathExists la saute (ni échec, ni bruit)."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
CLE = "/etc/secubox/secrets/annuaire/node.key"


def test_l_unite_offres_est_sautee_tant_que_la_cle_du_noeud_manque():
    u = (PAQUET / "systemd" / "secubox-annuaire-offres.service").read_text()
    unit = u[u.index("[Unit]"):u.index("[Service]")]
    assert re.search(rf"(?m)^ConditionPathExists={re.escape(CLE)}$", unit), "condition dans [Unit]"


def test_la_condition_vise_le_chemin_de_cle_du_code():
    """Un seul chemin de clé dans le paquet : celui de l'API et de sbx-fleetctl."""
    for f in ("api/main.py", "sbin/sbx-fleetctl"):
        assert CLE in (PAQUET / f).read_text(), f

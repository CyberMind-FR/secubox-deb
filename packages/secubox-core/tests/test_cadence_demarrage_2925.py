# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2925 — un drop-in de cadence ne doit pas laisser une minuterie sans declencheur de depart.

Dans systemd, vider UNE option OnXxxSec (« OnUnitActiveSec= ») remet a zero TOUTES les minuteries monotones
(OnBootSec, OnActiveSec, OnUnitActiveSec…). Les quatorze drop-ins de cadence ne laissaient donc que
OnUnitActiveSec=<intervalle>, qui ne part jamais sans activation prealable du service : minuterie « elapsed »,
echeance infinie (collecte netstats figee depuis le 14/10, annuaire depuis le 5/10 sur gk2)."""
import re
from pathlib import Path

CADENCE = Path(__file__).resolve().parents[1] / "systemd" / "cadence"


def _lignes(f):
    return [l.strip() for l in f.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#")]


def test_les_quatorze_drop_ins_sont_examines():
    assert len(list(CADENCE.glob("*.timer.conf"))) == 14


def test_apres_la_remise_a_zero_un_declencheur_de_depart_est_redonne():
    for f in sorted(CADENCE.glob("*.timer.conf")):
        l = _lignes(f)
        if any(re.fullmatch(r"OnCalendar=\S.*", x) for x in l):
            continue    # minuterie calendaire : elle part d'elle-meme
        reset = max((i for i, x in enumerate(l) if re.fullmatch(r"On\w+Sec=", x)), default=None)
        if reset is None:
            continue
        apres = l[reset + 1:]
        assert any(re.fullmatch(r"OnActiveSec=\d+\w*", x) for x in apres), f"{f.name} : rien ne demarre la minuterie"
        assert any(re.fullmatch(r"OnUnitActiveSec=\d+\w*", x) for x in apres), f.name

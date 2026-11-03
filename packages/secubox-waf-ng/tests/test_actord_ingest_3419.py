# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — secubox-actord-ingest n'est plus tué en plein travail par un redémarrage d'actord (Result=signal)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = (ROOT / "systemd" / "secubox-actord-ingest.service").read_text()
ACTORD = (ROOT / "systemd" / "secubox-actord.service").read_text()
SCRIPT = (ROOT / "sbin" / "secubox-actord-ingest-perms").read_text()


def test_ni_bindsto_ni_partof_mais_relance_par_actord():
    assert not re.search(r"^(BindsTo|PartOf)=", UNIT, re.M)
    assert re.search(r"^After=secubox-actord\.service$", UNIT, re.M)
    assert re.search(r"^Wants=secubox-actord-ingest\.service$", ACTORD, re.M)
    assert not re.search(r"^RemainAfterExit=", UNIT, re.M)


def test_attente_bornee_couverte_par_le_delai():
    attente = int(re.search(r"^ATTENTE=(\d+)", SCRIPT, re.M).group(1))
    delai = int(re.search(r"^TimeoutStartSec=(\d+)$", UNIT, re.M).group(1))
    assert delai > attente + 10
    assert SCRIPT.rstrip().endswith("exit 0")

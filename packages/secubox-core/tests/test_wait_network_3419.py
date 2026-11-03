# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3419 — secubox-network-ready ne bloque plus sur `netplan apply` (VM à une interface : échec en timeout)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "usr" / "bin" / "secubox-wait-network.sh").read_text()
UNIT = (ROOT / "systemd" / "secubox-network-ready.service").read_text()


def _code(texte):
    return "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))


def test_jamais_netplan_apply_et_appels_bornes():
    code = _code(SCRIPT)
    assert "netplan apply" not in code
    assert re.search(r"timeout \d+ netplan generate", code) and re.search(r"timeout \d+ networkctl reload", code)


def test_delai_de_l_unite_couvre_le_script():
    attente = int(re.search(r'SECUBOX_NET_TIMEOUT:-(\d+)', SCRIPT).group(1))
    bornes = sum(int(x) for x in re.findall(r"timeout (\d+) ", _code(SCRIPT)))
    delai = int(re.search(r"^TimeoutStartSec=(\d+)$", UNIT, re.M).group(1))
    assert delai > attente + bornes + 10

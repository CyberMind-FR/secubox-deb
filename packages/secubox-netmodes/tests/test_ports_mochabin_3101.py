# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3101 — rôles des ports MOCHAbin dans secubox-net-detect.

gk1, 2026-10-24 : detect donnait wan=eth0, lan="eth1 eth2 eth3 eth4". Sur MOCHAbin (net.ifnames=0) eth0 est le SFP+ 10G,
eth1 le conduit du switch DSA (jamais ponté), eth2 le WAN 1G RJ45 ; les ports LAN sont lan0..lan3. Appliqué, le mode
routeur pontait eth2 et eth1 dans br-lan : box hors réseau."""
import json
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-net-detect"


def _config(carte: str) -> dict:
    # le script se termine par « main "$@" » : on le charge sans cette ligne pour appeler une fonction
    code = SCRIPT.read_text().rsplit('main "$@"', 1)[0]
    r = subprocess.run(["bash", "-c", code + f'\nget_interface_config {carte}'], capture_output=True, text=True, check=True)
    return json.loads(r.stdout[r.stdout.index("{"):])


def test_mochabin_wan_eth2_lan_ports_du_switch_sfp_eth0():
    i = _config("mochabin")["interfaces"]
    assert i["wan"] == "eth2"
    assert i["lan"].split() == ["lan0", "lan1", "lan2", "lan3"]
    assert i["sfp"].split() == ["eth0"]


def test_mochabin_ne_ponte_jamais_le_conduit_dsa():
    i = _config("mochabin")["interfaces"]
    assert "eth1" not in (i["wan"] + " " + i["lan"] + " " + i["sfp"]).split()

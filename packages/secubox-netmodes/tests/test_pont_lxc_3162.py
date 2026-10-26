# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3162 — le netplan généré déclare toujours br-lxc (10.100.0.1/24, sans membre), passerelle des conteneurs LXC.

gk1, 2026-10-25 : le pont existait sans adresse (networkd : « unmanaged ») ; aucun conteneur n'atteignait 10.100.0.1."""
import subprocess
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-net-detect"


def _netplan(tmp_path, mode, lan="lan0 lan1 lan2 lan3", carte="mochabin", wan="eth2"):
    code = SCRIPT.read_text().rsplit('main "$@"', 1)[0]
    appel = f'\nNETPLAN_DIR="{tmp_path}"\ngenerate_netplan {carte} "{wan}" "{lan}" "" {mode}'
    subprocess.run(["bash", "-c", code + appel], capture_output=True, text=True, check=True)
    return yaml.safe_load((tmp_path / "00-secubox.yaml").read_text())["network"]


@pytest.mark.parametrize("mode,lan", [("router", "lan0 lan1 lan2 lan3"), ("router", ""), ("bridge", "lan0 lan1"), ("single", "")])
def test_br_lxc_toujours_declare(tmp_path, mode, lan):
    br = _netplan(tmp_path, mode, lan)["bridges"]["br-lxc"]
    assert br["interfaces"] == [] and br["addresses"] == ["10.100.0.1/24"] and br["optional"] is True
    assert "dhcp4" not in br or br["dhcp4"] is False


def test_br_lan_inchange_en_mode_routeur(tmp_path):
    # hors MOCHAbin (#3189 : sur MOCHAbin br-lan appartient au mode routeur durable)
    b = _netplan(tmp_path, "router", carte="espressobin-v7")["bridges"]
    assert b["br-lan"]["interfaces"] == ["lan0", "lan1", "lan2", "lan3"] and b["br-lan"]["addresses"] == ["192.168.10.1/24"]


def test_routeur_sans_lan_ne_cree_pas_de_br_lan(tmp_path):
    assert "br-lan" not in _netplan(tmp_path, "router", "")["bridges"]

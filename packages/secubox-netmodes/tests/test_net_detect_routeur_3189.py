# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3189 — secubox-net-detect sur MOCHAbin : plus de br-lan au netplan, WAN déjà configuré jamais relancé.

Le WAN eth2 (mvpp2) se bloque si son lien est relancé à distance (redémarrage à froid) : sur un MOCHAbin dont le WAN
porte déjà une IPv4, `apply` ne réécrit pas le netplan et ne lance pas `netplan apply`. Le mode routeur durable pose
br-lan par des fichiers networkd : deux propriétaires se battraient."""
import os
import stat
import subprocess
from pathlib import Path

import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-net-detect"


def _code() -> str:
    return SCRIPT.read_text().rsplit('main "$@"', 1)[0]


def _run(tmp_path: Path, corps: str, ipv4_wan: bool = False, carte: str = "mochabin"):
    """Exécute `corps` après chargement du script ; faux ip/netplan dans tmp_path/bin, NETPLAN_DIR dans tmp_path."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    appels = tmp_path / "appels.log"
    ip = bin_dir / "ip"
    ip.write_text('#!/bin/sh\n[ "$*" = "-4 -o addr show dev eth2" ] && %s\nexit 0\n'
                  % ('echo "2: eth2    inet 192.168.1.5/24 brd 192.168.1.255 scope global eth2"' if ipv4_wan else ":"))
    np = bin_dir / "netplan"
    np.write_text(f'#!/bin/sh\necho "netplan $*" >> {appels}\nexit 0\n')
    for f in (ip, np):
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
    netplan_dir = tmp_path / "netplan"
    netplan_dir.mkdir(exist_ok=True)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")
    script = _code() + f'\nNETPLAN_DIR="{netplan_dir}"\ndetect_board() {{ echo {carte}; }}\n{corps}\n'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    return r, netplan_dir / "00-secubox.yaml", appels


def test_mochabin_routeur_sans_br_lan(tmp_path):
    r, f, _ = _run(tmp_path, 'generate_netplan mochabin eth2 "lan0 lan1 lan2 lan3" eth0 router')
    assert r.returncode == 0, r.stderr
    bridges = yaml.safe_load(f.read_text())["network"]["bridges"]
    assert "br-lan" not in bridges
    assert "br-lxc" in bridges


def test_autres_cartes_inchangees(tmp_path):
    r, f, _ = _run(tmp_path, 'generate_netplan espressobin-v7 wan "lan0 lan1" "" router')
    assert r.returncode == 0, r.stderr
    assert "br-lan" in yaml.safe_load(f.read_text())["network"]["bridges"]


def test_wan_configure_ni_reecriture_ni_apply(tmp_path):
    r, f, appels = _run(tmp_path, "main apply router", ipv4_wan=True)
    assert r.returncode == 0, r.stderr
    assert not f.exists()
    assert not appels.exists()
    assert "eth2" in r.stdout and "mvpp2" in r.stdout
    assert "netmodesctl" in r.stdout


def test_wan_sans_adresse_comportement_actuel(tmp_path):
    r, f, appels = _run(tmp_path, "main apply router", ipv4_wan=False)
    assert r.returncode == 0, r.stderr
    assert f.exists()
    assert "netplan apply" in appels.read_text()

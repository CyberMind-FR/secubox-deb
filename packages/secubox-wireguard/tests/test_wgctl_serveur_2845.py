# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#2845 — `wgctl serveur init` : la box offre la sortie Internet à des clients WireGuard.

Une box derrière NAT (ESPRESSObin enrôlée Auto-Load) n'est pas joignable par son IP publique : le point d'accès écrit dans les configurations clientes doit être
celui du relais (gk2), pas celui que `peer add` devine. Le script s'exécute sur une COPIE dont les chemins /etc et /var sont déplacés sous un dossier temporaire,
avec `wg`, `nft`, `systemctl`, `sysctl` doublés : rien n'est touché sur la machine.
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "wgctl"
CLE = "kPrivateKeyOfTheServerxxxxxxxxxxxxxxxxxxxx="


def _exe(p: Path, corps: str):
    p.write_text("#!/usr/bin/env bash\n" + corps)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def banc(tmp_path):
    b = tmp_path / "bin"
    b.mkdir()
    script = tmp_path / "wgctl"
    src = CTL.read_text()
    script.write_text(re.sub(r'"/(etc|var)/', rf'"{tmp_path}/\1/', src))
    lances = tmp_path / "lances.txt"
    _exe(b / "wg", f'case "$1" in genkey) echo "{CLE}";; pubkey) echo "pubSrvxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=";; genpsk) echo "psk=";; show) exit 1;; *) exit 1;; esac\n')
    for outil in ("nft", "systemctl", "sysctl"):
        _exe(b / outil, f'echo "{outil} $*" >> "{lances}"; exit 0\n')
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}")
    return tmp_path, script, env, lances


def _ctl(banc, *args):
    tmp, script, env, _ = banc
    return subprocess.run(["bash", str(script), *args], env=env, capture_output=True, text=True, timeout=30)


def test_init_cree_l_interface_serveur_et_ses_regles(banc):
    tmp, _, _, lances = banc
    r = _ctl(banc, "serveur", "init", "--endpoint", "lgm-ebin.secubox.in:51840")
    assert r.returncode == 0, r.stdout + r.stderr
    conf = tmp / "etc" / "wireguard" / "wg-clients.conf"
    texte = conf.read_text()
    assert "Address = 10.66.0.1/24" in texte and "ListenPort = 51820" in texte and f"PrivateKey = {CLE}" in texte
    assert stat.S_IMODE(conf.stat().st_mode) == 0o600
    nft = (tmp / "etc" / "secubox" / "wireguard-clients.nft").read_text()
    assert "masquerade" in nft and "10.66.0.0/24" in nft and 'iifname "wg-clients" accept' in nft
    assert "PostUp = nft -f" in texte and "PostDown = nft delete table inet secubox_wg_clients" in texte
    assert (tmp / "etc" / "secubox" / "wireguard-endpoint").read_text().strip() == "lgm-ebin.secubox.in:51840"
    assert "net.ipv4.ip_forward=1" in (tmp / "etc" / "sysctl.d" / "90-secubox-wg-clients.conf").read_text()
    assert "systemctl enable --now wg-quick@wg-clients" in lances.read_text()


def test_init_est_idempotent_et_ne_change_jamais_la_cle(banc):
    tmp, _, _, _ = banc
    _ctl(banc, "serveur", "init")
    conf = tmp / "etc" / "wireguard" / "wg-clients.conf"
    conf.write_text(conf.read_text().replace(CLE, "AutreClexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="))
    r = _ctl(banc, "serveur", "init")
    assert r.returncode == 0 and "AutreCle" in conf.read_text() and CLE not in conf.read_text()


@pytest.mark.parametrize("args", [
    ("serveur", "init", "--endpoint", "x;id:51840"),
    ("serveur", "init", "--endpoint", "sans-port"),
    ("serveur", "init", "--endpoint", "h:99999"),
    ("serveur", "init", "--port", "0"),
    ("serveur", "init", "--port", "abc"),
    ("serveur", "init", "--inconnue", "1"),
])
def test_arguments_hostiles_refuses(banc, args):
    r = _ctl(banc, *args)
    assert r.returncode == 64, (args, r.stdout + r.stderr)
    assert not (banc[0] / "etc" / "wireguard" / "wg-clients.conf").exists()


def test_serveur_est_un_verbe_d_operateur(banc):
    tmp, script, env, _ = banc
    r = subprocess.run(["bash", str(script), "serveur", "init"], env=dict(env, SUDO_USER="secubox"), capture_output=True, text=True, timeout=30)
    assert r.returncode == 64 and not (tmp / "etc" / "wireguard" / "wg-clients.conf").exists()


def test_peer_add_ecrit_le_point_d_acces_configure(banc):
    tmp, _, env, _ = banc
    _ctl(banc, "serveur", "init", "--endpoint", "lgm-ebin.secubox.in:51840")
    _exe(tmp / "bin" / "wg", f'case "$1" in genkey) echo "{CLE}";; pubkey) echo "pubxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=";; genpsk) echo "psk=";; show) case "$2 $3" in "wg-clients public-key") echo "pubSrv=";; "wg-clients listen-port") echo 51820;; *) true;; esac;; set) exit 0;; *) exit 0;; esac\n')
    _exe(tmp / "bin" / "curl", 'echo 203.0.113.9\n')
    r = _ctl(banc, "peer", "add", "telephone", "wg-clients")
    assert r.returncode == 0, r.stdout + r.stderr
    client = (tmp / "var" / "lib" / "secubox" / "wireguard" / "peers" / "telephone.conf").read_text()
    assert "Endpoint = lgm-ebin.secubox.in:51840" in client and "203.0.113.9" not in client

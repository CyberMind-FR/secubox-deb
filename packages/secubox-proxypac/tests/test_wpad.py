# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import subprocess, os, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def _run(env, *args):
    return subprocess.run(["bash", str(ROOT/"sbin/proxypac-wpad"), *args],
                          capture_output=True, text=True, env=env)

def _env(tmp, role="master"):
    return {**os.environ, "WPAD_DRYRUN": "1", "WPAD_ROLE": role,
            "WPAD_DNSMASQ_D": str(tmp/"dnsmasq"), "WPAD_UNBOUND_D": str(tmp/"unbound"),
            "WPAD_DOMAIN": "gk2.secubox.in", "WPAD_LAN_IP": "192.168.1.200"}

def test_master_writes_dhcp_option_252(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    r = _run(_env(tmp_path, "master"), "apply")
    assert r.returncode == 0
    f = tmp_path/"dnsmasq"/"secubox-wpad.conf"
    assert f.exists() and "dhcp-option=252" in f.read_text() and "wpad.gk2.secubox.in" in f.read_text()

def test_slave_tier2_writes_unbound_wpad_record(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    r = _run(_env(tmp_path, "slave-dns"), "apply")
    assert r.returncode == 0
    f = tmp_path/"unbound"/"secubox-wpad.conf"
    assert f.exists() and "wpad.gk2.secubox.in" in f.read_text() and "192.168.1.200" in f.read_text()
    assert not (tmp_path/"dnsmasq"/"secubox-wpad.conf").exists()

def test_idempotent(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    e = _env(tmp_path, "master")
    _run(e, "apply"); a = (tmp_path/"dnsmasq"/"secubox-wpad.conf").read_text()
    _run(e, "apply"); b = (tmp_path/"dnsmasq"/"secubox-wpad.conf").read_text()
    assert a == b

def test_toml_role_master_override_forces_master(tmp_path):
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    toml = tmp_path/"proxypac.toml"; toml.write_text('role = "master"\n')
    env = {k:v for k,v in os.environ.items()}
    env.update({"WPAD_DRYRUN":"1","WPAD_DNSMASQ_D":str(tmp_path/"dnsmasq"),
                "WPAD_UNBOUND_D":str(tmp_path/"unbound"),"WPAD_DOMAIN":"gk2.secubox.in",
                "WPAD_LAN_IP":"192.168.1.200","WPAD_CONFIG":str(toml)})
    # PAS de WPAD_ROLE -> doit lire le toml
    env.pop("WPAD_ROLE", None)
    r = _run(env, "apply")
    assert r.returncode == 0
    assert (tmp_path/"dnsmasq"/"secubox-wpad.conf").exists(), "role=master du toml doit forcer l'échelon master"

def test_role_switch_cleans_previous_tier(tmp_path):
    # Bascule master -> slave-dns SUR LES MÊMES répertoires : le dropin de
    # l'ancien tier DOIT disparaître (pas d'accumulation des deux).
    (tmp_path/"dnsmasq").mkdir(); (tmp_path/"unbound").mkdir()
    dnsmasq = tmp_path/"dnsmasq"/"secubox-wpad.conf"
    unbound = tmp_path/"unbound"/"secubox-wpad.conf"
    _run(_env(tmp_path, "master"), "apply")
    assert dnsmasq.exists() and not unbound.exists()
    _run(_env(tmp_path, "slave-dns"), "apply")
    assert unbound.exists() and not dnsmasq.exists(), "l'ancien dropin master doit être nettoyé"
    # et retour à tier3 (slave) : plus aucun dropin
    _run(_env(tmp_path, "slave"), "apply")
    assert not dnsmasq.exists() and not unbound.exists()

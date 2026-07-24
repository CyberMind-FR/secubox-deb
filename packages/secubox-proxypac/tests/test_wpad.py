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

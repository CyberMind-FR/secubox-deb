import subprocess, os, json, stat
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def _run(env, *args):
    return subprocess.run(["bash", str(ROOT/"sbin/torctl"), *args],
                          capture_output=True, text=True, env=env)

def test_on_skips_transport_dropin_when_one_already_exists(tmp_path):
    torrc = tmp_path/"torrc.d"; torrc.mkdir()
    (torrc/"torrc-toolbox-egress.conf").write_text("TransPort 127.0.0.1:9040\nDNSPort 127.0.0.1:9053\n")
    env = {**os.environ, "TORCTL_TORRC_D": str(torrc), "TORCTL_UNBOUND_D": str(tmp_path/"u"),
           "TORCTL_NFT_D": str(tmp_path/"n"), "TORCTL_DRYRUN": "1"}
    (tmp_path/"u").mkdir(); (tmp_path/"n").mkdir()
    r = _run(env, "transparent", "on")
    assert r.returncode == 0
    assert not (torrc/"60-secubox-transparent.conf").exists(), "ne doit pas dupliquer TransPort"

def test_off_removes_only_our_files(tmp_path):
    torrc = tmp_path/"torrc.d"; torrc.mkdir()
    ext = torrc/"torrc-toolbox-egress.conf"; ext.write_text("TransPort 127.0.0.1:9040\n")
    (torrc/"60-secubox-transparent.conf").write_text("x")
    env = {**os.environ, "TORCTL_TORRC_D": str(torrc), "TORCTL_UNBOUND_D": str(tmp_path/"u"),
           "TORCTL_NFT_D": str(tmp_path/"n"), "TORCTL_DRYRUN": "1"}
    (tmp_path/"u").mkdir(); (tmp_path/"n").mkdir()
    _run(env, "transparent", "off")
    assert not (torrc/"60-secubox-transparent.conf").exists()
    assert ext.exists(), "off ne doit jamais retirer le dropin d'un autre paquet"

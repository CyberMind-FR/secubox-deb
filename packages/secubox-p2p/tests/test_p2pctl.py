# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys
from pathlib import Path

CTL = str(Path(__file__).resolve().parent.parent / "sbin" / "secubox-p2pctl")
P2P = str(Path(__file__).resolve().parent.parent)


def _env(tmp_path):
    env = dict(os.environ)
    # a fake `wg`/`ip` that records argv and always succeeds
    rec = tmp_path / "wgcalls.log"
    fake = tmp_path / "fakebin"; fake.write_text(
        "#!/bin/sh\necho \"$0 $*\" >> " + str(rec) + "\nexit 0\n")
    fake.chmod(0o755)
    env.update(P2P_LIB=P2P, PYTHONPATH=os.pathsep.join([P2P, env.get("PYTHONPATH", "")]),
               P2P_WG_BIN=str(fake), P2P_IP_BIN=str(fake),
               P2P_EPHEMERAL_REGISTRY=str(tmp_path / "ephemeral.json"),
               P2P_BOOT_ID="fixed-boot")
    return env, rec


def test_peer_add_records_and_calls_wg(tmp_path):
    env, rec = _env(tmp_path)
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "1.2.3.4:51820",
                        "--ip", "10.11.0.2", "--allowed-ip", "10.11.0.2/32",
                        "--ttl", "3600"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    reg = json.loads((tmp_path / "ephemeral.json").read_text())
    assert reg["peers"][0]["pubkey"] == "PK" and reg["peers"][0]["ip"] == "10.11.0.2"
    assert "peer PK" in rec.read_text() or "PK" in rec.read_text()  # wg set peer called


def test_peer_add_rejects_out_of_range_and_non_ephemeral(tmp_path):
    env, _ = _env(tmp_path)
    # out of range
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                        "--allowed-ip", "10.10.0.2/32"], env=env, capture_output=True, text=True)
    assert r.returncode == 1 and json.loads(r.stderr)["error"]
    # missing --ephemeral
    r2 = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                         "--pubkey", "PK", "--endpoint", "e",
                         "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r2.returncode == 1 and json.loads(r2.stderr)["error"]


def test_peer_del_and_revoke_idempotent(tmp_path):
    env, _ = _env(tmp_path)
    subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                    "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                    "--allowed-ip", "10.11.0.2/32", "--did", "did:plc:" + "a"*32],
                   env=env, check=True, capture_output=True, text=True)
    r = subprocess.run([sys.executable, CTL, "peer-del", "--iface", "wg-ephemeral",
                        "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r.returncode == 0
    # deleting again is a no-op success
    r2 = subprocess.run([sys.executable, CTL, "peer-del", "--iface", "wg-ephemeral",
                         "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r2.returncode == 0


def test_dryrun_writes_nothing(tmp_path):
    env, rec = _env(tmp_path); env["DRYRUN"] = "1"
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "e",
                        "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert json.loads(r.stdout).get("dryrun") is True
    assert not (tmp_path / "ephemeral.json").exists()
    assert not rec.exists()


def test_peer_add_save_failure_is_json_not_traceback(tmp_path):
    env, _ = _env(tmp_path)
    env["P2P_EPHEMERAL_REGISTRY"] = str(tmp_path / "nonexistent-dir" / "ephemeral.json")
    r = subprocess.run([sys.executable, CTL, "peer-add", "--iface", "wg-ephemeral",
                        "--ephemeral", "--pubkey", "PK", "--endpoint", "1.2.3.4:51820",
                        "--allowed-ip", "10.11.0.2/32"], env=env, capture_output=True, text=True)
    assert r.returncode == 1
    assert "Traceback" not in r.stderr
    assert json.loads(r.stderr)["error"]

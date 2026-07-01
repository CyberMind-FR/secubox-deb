# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, subprocess, sys, pathlib
PLUG = str(pathlib.Path(__file__).resolve().parents[1] / "macros.d" / "tor-exit")


def _fake_nft(tmp_path):
    # a fake `nft` that records its argv to a file and exits 0
    d = tmp_path / "bin"; d.mkdir()
    rec = tmp_path / "nft.calls"
    fake = d / "nft"
    fake.write_text("#!/usr/bin/env bash\necho \"$@\" >> " + str(rec) + "\n")
    fake.chmod(0o755)
    return str(fake), rec


def _env(tmp_path):
    fake, rec = _fake_nft(tmp_path)
    return dict(os.environ, TOREXIT_NFT=fake, TOREXIT_MESH_IP="10.10.0.1",
               TOREXIT_STATE_DIR=str(tmp_path / "active"),
               TOREXIT_SET="secubox_macro_torexit", TOREXIT_TABLE="inet secubox_filter"), rec


def _run(args, env):
    return subprocess.run([PLUG] + args, capture_output=True, text=True, env=env)


def test_grant_emits_endpoint_and_adds_set(tmp_path):
    env, rec = _env(tmp_path)
    r = _run(["grant", "--sub", "did:plc:" + "a" * 32, "--src-ip", "10.10.0.2",
              "--params", json.dumps({"socks_port": 9050})], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["endpoint"] == "10.10.0.1:9050"
    calls = rec.read_text()
    assert "10.10.0.2" in calls and "secubox_macro_torexit" in calls and "add" in calls


def test_revoke_removes_set(tmp_path):
    env, rec = _env(tmp_path)
    r = _run(["revoke", "--sub", "did:plc:" + "a" * 32, "--src-ip", "10.10.0.2",
              "--params", "{}"], env)
    assert r.returncode == 0
    assert "delete" in rec.read_text() and "10.10.0.2" in rec.read_text()


def test_activate_writes_state(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["activate", "--cred", json.dumps({"endpoint": "10.10.0.1:9050",
              "service_id": "svc1"})], env)
    assert r.returncode == 0
    st = pathlib.Path(env["TOREXIT_STATE_DIR"]) / "svc1.json"
    assert st.exists() and "10.10.0.1:9050" in st.read_text()

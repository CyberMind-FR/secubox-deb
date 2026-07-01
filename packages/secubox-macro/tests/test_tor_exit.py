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


def test_activate_sanitizes_traversal_service_id(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["activate", "--cred", json.dumps({"endpoint": "10.10.0.1:9050",
              "service_id": "../../etc/evil"})], env)
    assert r.returncode == 0
    state_dir = pathlib.Path(env["TOREXIT_STATE_DIR"])
    json_files = list(state_dir.glob("*.json"))
    # Exactly one .json file must exist inside STATE_DIR
    assert len(json_files) == 1, f"expected 1 json in state dir, got {json_files}"
    fname = json_files[0].name
    # The filename must not contain path separators or dots
    assert "/" not in fname
    assert ".." not in fname
    # The sanitized name must be the clean form of the traversal input
    assert fname == "______etc_evil.json"


def test_grant_bad_socks_port_clean_json_error(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["grant", "--src-ip", "10.10.0.2",
              "--params", json.dumps({"socks_port": "bad"})], env)
    assert r.returncode != 0
    out = json.loads(r.stdout)
    assert "socks_port" in out.get("error", ""), \
        f"expected 'socks_port' in error JSON, got: {r.stdout!r}"


def test_grant_out_of_range_port_rejected(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["grant", "--src-ip", "10.10.0.2",
              "--params", json.dumps({"socks_port": 99999})], env)
    assert r.returncode != 0


def _load_plugin_module():
    """Import the tor-exit plugin (a shebang script, no .py) as a module so we
    can unit-test its pure helpers."""
    import pathlib
    from importlib.machinery import SourceFileLoader
    p = pathlib.Path(__file__).resolve().parents[1] / "macros.d" / "tor-exit"
    return SourceFileLoader("torexit_plugin", str(p)).load_module()


def test_conf_table_reads_valid(tmp_path):
    mod = _load_plugin_module()
    conf = tmp_path / "macro.conf"
    conf.write_text("TOREXIT_TABLE=inet filter\n")
    assert mod._conf_table(str(conf)) == "inet filter"


def test_conf_table_rejects_injection(tmp_path):
    mod = _load_plugin_module()
    conf = tmp_path / "macro.conf"
    conf.write_text("TOREXIT_TABLE=inet filter; rm -rf /\n")  # malicious
    assert mod._conf_table(str(conf)) == "inet secubox_filter"  # rejected → default


def test_conf_table_default_when_absent(tmp_path):
    mod = _load_plugin_module()
    assert mod._conf_table(str(tmp_path / "nope.conf")) == "inet secubox_filter"

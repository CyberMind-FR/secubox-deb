# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json, os, stat, subprocess, sys, pathlib
CTL = str(pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-macroctl")


def _run(args, env):
    return subprocess.run([sys.executable, CTL] + args, capture_output=True, text=True, env=env)


def _env(tmp_path):
    d = tmp_path / "macros.d"; d.mkdir()
    plug = d / "echo"
    plug.write_text("#!/usr/bin/env python3\n"
                    "import json,sys\n"
                    "print(json.dumps({'ok': True, 'argv': sys.argv[1:]}))\n")
    plug.chmod(0o755)
    e = dict(os.environ, MACRO_PLUGIN_DIR=str(d),
             MACRO_AUDIT_LOG=str(tmp_path / "audit.log"),
             MACRO_MESH_CIDR="10.10.0.0/24")
    return e


def test_rejects_unknown_kind(tmp_path):
    r = _run(["nope", "grant"], _env(tmp_path))
    assert r.returncode != 0
    assert "unknown" in (r.stdout + r.stderr).lower() or "error" in (r.stdout + r.stderr).lower()


def test_rejects_path_traversal_kind(tmp_path):
    r = _run(["../secrets", "grant"], _env(tmp_path))
    assert r.returncode != 0


def test_rejects_src_ip_outside_mesh(tmp_path):
    r = _run(["echo", "grant", "--src-ip", "192.168.1.5"], _env(tmp_path))
    assert r.returncode != 0
    assert "mesh" in (r.stdout + r.stderr).lower() or "10.10.0" in (r.stdout + r.stderr)


def test_dispatches_to_plugin_and_audits(tmp_path):
    env = _env(tmp_path)
    r = _run(["echo", "grant", "--sub", "did:plc:" + "a"*32, "--src-ip", "10.10.0.2"], env)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["ok"] is True
    audit = pathlib.Path(env["MACRO_AUDIT_LOG"]).read_text()
    assert "echo" in audit and "grant" in audit


def test_refuses_non_root_owned_or_world_writable_plugin(tmp_path):
    env = _env(tmp_path)
    plug = pathlib.Path(env["MACRO_PLUGIN_DIR"]) / "echo"
    plug.chmod(0o777)  # world-writable → tamper risk
    r = _run(["echo", "grant", "--src-ip", "10.10.0.2"], env)
    assert r.returncode != 0


def test_grant_requires_src_ip(tmp_path):
    r = _run(["echo", "grant"], _env(tmp_path))  # no --src-ip
    assert r.returncode != 0
    assert "src-ip" in (r.stdout + r.stderr).lower()


def test_revoke_requires_src_ip(tmp_path):
    r = _run(["echo", "revoke"], _env(tmp_path))
    assert r.returncode != 0


def test_activate_does_not_require_src_ip(tmp_path):
    r = _run(["echo", "activate", "--cred", "{}"], _env(tmp_path))
    assert r.returncode == 0  # activate needs no src-ip

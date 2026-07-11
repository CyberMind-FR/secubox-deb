# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""secubox-publishctl argument validation (run the script with a fake route file
and mocked nft/haproxy/certbot on PATH — validation must reject junk BEFORE any
privileged call)."""
import json
import os
import subprocess
from pathlib import Path

HELPER = Path(__file__).resolve().parents[2] / "sbin" / "secubox-publishctl"


def _run(args, env):
    return subprocess.run(["bash", str(HELPER), *args], capture_output=True, text=True, env=env)


def _env(tmp_path):
    # Fake bins that just succeed, so a VALID call would pass; validation must
    # fail earlier for bad input.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("haproxyctl", "systemctl", "certbot", "haproxy"):
        p = bindir / name
        p.write_text("#!/bin/bash\nexit 0\n")
        p.chmod(0o755)
    routes = tmp_path / "routes.json"
    routes.write_text("{}")
    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SBX_WAF_ROUTES_FILE"] = str(routes)
    env["SBX_HAPROXY_CERTS_DIR"] = str(tmp_path / "certs")
    return env, routes


def test_waf_route_rejects_bad_domain(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "evil;rm -rf /", "8900"], env)
    assert r.returncode != 0
    assert "ok" in r.stdout and json.loads(r.stdout)["ok"] is False


def test_waf_route_rejects_non_numeric_port(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["waf-route", "good.gk2.secubox.in", "80x"], env)
    assert r.returncode != 0


def test_waf_route_writes_host_backend(tmp_path):
    env, routes = _env(tmp_path)
    r = _run(["waf-route", "zem.gk2.secubox.in", "8900"], env)
    assert r.returncode == 0, r.stderr
    data = json.loads(routes.read_text())
    assert data["zem.gk2.secubox.in"] == ["192.168.1.200", 8900]


def test_cert_wildcard_is_noop_for_gk2(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["cert", "zem.gk2.secubox.in"], env)
    assert r.returncode == 0
    assert json.loads(r.stdout)["detail"] == "wildcard"


def test_unknown_verb_fails(tmp_path):
    env, _ = _env(tmp_path)
    r = _run(["frobnicate", "x"], env)
    assert r.returncode != 0

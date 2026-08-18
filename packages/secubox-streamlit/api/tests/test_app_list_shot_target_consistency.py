# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Regression tests for #958 — `app list` and `app shot-target` used two
independent, contradicting detection paths.

Measured on the board: 15 streamlit apps really running, 15 ports really
listening, but `streamlitctl app list` reported only 3 as "running" (with
"port": 0), and `streamlitctl app shot-target <name>` answered
{"ok":false,"error":"not running"} for an app that `app list` had *just*
reported "running": true for.

Two things the old code got wrong, both reproduced here from real `ps -eo
args` lines captured in the streamlit LXC:

  1. `app list` built its own process-matching (a raw sed one-liner) and
     read the port from the per-app `.streamlit.toml` — never from the
     process itself. `app shot-target` went through `_app_running`, which
     also read the port from that same `.streamlit.toml` and then checked
     `ss` for it. Neither path looked at the *live* `--server.port` the
     process was actually started with, so a stale/missing config file
     produced port 0 (`app list`) or a false "not running" (`shot-target`)
     even though the process was genuinely up.

  2. The port can be passed two ways: `--server.port 8509` (space —
     observed on processes not started via this script's own launch path,
     which uses `=`) and `--server.port=8509`. An analyzer expecting only
     one form misses the other.

  3. The entry point can be a flat script (`bazi_complete.py`,
     `secubox_control.py`) or nested one level down (`secubox_evolution/
     app.py`). `app list` used to iterate directories only, silently
     dropping every flat-script app from the wall entirely.

The fix routes both verbs through the single `_scan_running_apps` process
matcher (also reused by `app audit`/`app repair`).
"""
import json
import subprocess
import stat
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"

# Real `ps -eo args` lines captured in the streamlit LXC (#958). Port
# passed with a space, not `=` — the processes were not all launched via
# this script's own `--server.port=$port` path.
REAL_PS_LINES = (
    "/usr/bin/python3 /usr/local/bin/streamlit run bazi_complete.py "
    "--server.port 8509 --server.address 0.0.0.0 --server.headless true "
    "--browser.gatherUsageStats false\n"
    "/usr/bin/python3 /usr/local/bin/streamlit run secubox_evolution/app.py "
    "--server.port 8510 --server.address 0.0.0.0 --server.headless true "
    "--browser.gatherUsageStats false\n"
    "/usr/bin/python3 /usr/local/bin/streamlit run secubox_control.py "
    "--server.port 8511 --server.address 0.0.0.0 --server.headless true "
    "--browser.gatherUsageStats false\n"
)


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path, ip: str = "10.20.30.40") -> None:
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
shift 2
if [ "$1" = "-s" ]; then echo "State: RUNNING"; exit 0; fi
if [ "$1" = "-i" ]; then echo "{ip}"; exit 0; fi
exit 1
""".format(ip=ip))


def _make_apps_tree(apps_dir: Path) -> None:
    (apps_dir / "bazi_complete.py").write_text("import streamlit\n")
    (apps_dir / "secubox_control.py").write_text("import streamlit\n")
    evo = apps_dir / "secubox_evolution"
    evo.mkdir()
    (evo / "app.py").write_text("import streamlit\n")


def _env(tmp_path, apps_dir, conf, ps_file, extra_path=None):
    base = "/usr/bin:/bin:/usr/sbin:/sbin"
    path = "{}:{}".format(extra_path, base) if extra_path else base
    return {
        "PATH": path,
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_file),
    }


def _run_list(tmp_path, apps_dir, conf, ps_file):
    env = _env(tmp_path, apps_dir, conf, ps_file)
    r = subprocess.run(["bash", str(CTL), "app", "list"],
                        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads(r.stdout)


def _run_shot_target(tmp_path, name, apps_dir, conf, ps_file, extra_path=None):
    env = _env(tmp_path, apps_dir, conf, ps_file, extra_path)
    return subprocess.run(["bash", str(CTL), "app", "shot-target", name],
                           capture_output=True, text=True, env=env, timeout=30)


def test_app_list_sees_all_three_real_processes_with_their_real_port(tmp_path):
    """The three real ps lines above must all show up as running, with the
    exact port each process was started with — none of them ever wrote a
    matching .streamlit.toml, so a config-file-based port lookup gives 0."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    _make_apps_tree(apps_dir)
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"; ps_file.write_text(REAL_PS_LINES)

    out = _run_list(tmp_path, apps_dir, conf, ps_file)
    by_name = {a["name"]: a for a in out["apps"]}

    assert set(by_name) == {"bazi_complete", "secubox_control", "secubox_evolution"}
    assert by_name["bazi_complete"]["running"] is True
    assert by_name["bazi_complete"]["port"] == 8509
    assert by_name["secubox_control"]["running"] is True
    assert by_name["secubox_control"]["port"] == 8511
    assert by_name["secubox_evolution"]["running"] is True
    assert by_name["secubox_evolution"]["port"] == 8510


def test_shot_target_agrees_with_app_list_for_every_real_process(tmp_path):
    """shot-target must answer ok:true, with the SAME port app list just
    reported, for every one of the three apps app list called running.
    Before the fix, shot-target used a completely different detection
    path (persisted .streamlit.toml + a per-app `ss` check) and answered
    "not running" here even though app list said running:true."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    _make_apps_tree(apps_dir)
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"; ps_file.write_text(REAL_PS_LINES)
    _mock_lxc_info(tmp_path, ip="10.20.30.40")

    listed = _run_list(tmp_path, apps_dir, conf, ps_file)
    ports = {a["name"]: a["port"] for a in listed["apps"]}

    for name in ("bazi_complete", "secubox_control", "secubox_evolution"):
        r = _run_shot_target(tmp_path, name, apps_dir, conf, ps_file,
                              extra_path=str(tmp_path))
        assert r.returncode == 0, f"{name}: {r.stdout}{r.stderr}"
        assert '"ok":true' in r.stdout, f"{name}: {r.stdout}"
        assert f'"url":"http://10.20.30.40:{ports[name]}/"' in r.stdout, \
            f"{name}: expected port {ports[name]} to match app list, got {r.stdout}"


def test_port_passed_with_a_space_is_recognized(tmp_path):
    """--server.port 8509 (space, not '='): the launch path in this file
    always uses '=', but processes already alive on the board were not
    all started that way."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "spaced.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run spaced.py --server.port 8509\n")

    out = _run_list(tmp_path, apps_dir, conf, ps_file)
    app = out["apps"][0]
    assert app["name"] == "spaced"
    assert app["running"] is True
    assert app["port"] == 8509


def test_port_passed_with_equals_is_recognized(tmp_path):
    """--server.port=8509 (equals) — the form this file's own launch path
    produces."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "eq.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run eq.py --server.port=8510\n")

    out = _run_list(tmp_path, apps_dir, conf, ps_file)
    app = out["apps"][0]
    assert app["name"] == "eq"
    assert app["running"] is True
    assert app["port"] == 8510


def test_flat_entrypoint_is_listed_and_matched(tmp_path):
    """A flat script directly under APPS_PATH (no subdirectory) must be
    listed at all, and matched to its running process."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "flat_app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run flat_app.py --server.port=8520\n")

    out = _run_list(tmp_path, apps_dir, conf, ps_file)
    assert len(out["apps"]) == 1
    app = out["apps"][0]
    assert app["name"] == "flat_app"
    assert app["running"] is True
    assert app["port"] == 8520


def test_subdirectory_entrypoint_is_matched_to_its_directory_name(tmp_path):
    """dir_app/app.py must be matched to the app named 'dir_app', not to
    some literal "app" name derived from the script's own basename."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "dir_app"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run dir_app/app.py --server.port=8530\n")

    out = _run_list(tmp_path, apps_dir, conf, ps_file)
    assert len(out["apps"]) == 1
    app = out["apps"][0]
    assert app["name"] == "dir_app"
    assert app["running"] is True
    assert app["port"] == 8530

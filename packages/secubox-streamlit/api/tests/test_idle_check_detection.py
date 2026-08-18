# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for `streamlitctl app idle-check` detection (#958 follow-up).

Measured on the board: `streamlitctl app idle-check` reported
`active=0 idle=0 stopped=0` while 24 Streamlit apps were genuinely
running in the container. The cause is the same class of bug #958 already
fixed for `app list` / `app shot-target`: this verb iterated ONLY over
subdirectories of APPS_PATH (`for app_dir in "$APPS_PATH"/*/`) — silently
dropping every flat-script app, which is most of the fleet (#959) — and
judged "running" via `_app_running`/`_app_port_file`, which reads the port
from the per-app `.streamlit.toml`. That file is only ever written by the
`app start`/`app wake` code path; processes alive some other way (or
started before that path existed) never get one. On the board: 24 running
apps, only 17 `.streamlit.toml` files.

The fix routes `idle-check` through the same `_scan_running_apps` matcher
`app list`/`app audit`/`app shot-target` already use (#958) — a single
`_ps_lines()`/`lxc-attach` call for the whole fleet, port taken from the
live `--server.port` the process was actually started with.

This module also pins the safety behavior this verb absolutely must not
regress on, since a false "idle" verdict here stops a live application:
  - an app with an ESTABLISHED connection is NEVER a stop candidate;
  - an app with no recorded last-activity timestamp yet (first time seen)
    is NOT stopped immediately — it is granted a grace period instead;
  - an app whose recorded timestamp is in the future (clock skew /
    corrupt state) is likewise granted a grace period, not stopped;
  - `--dry-run` reports candidates without ever calling `cmd_app_stop` and
    without mutating idle-state timestamps, so a dry run is replayable.
"""
import os
import stat
import subprocess
import time
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path) -> None:
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
shift 2  # drop -n <name>
if [ "$1" = "-s" ]; then
    echo "State: RUNNING"
    exit 0
fi
exit 1
""")


def _mock_lxc_attach(tmp_path: Path, stop_log: Path, established_ports=()) -> None:
    """Stands in for lxc-attach for the two calls `idle-check` makes once
    it has resolved a port via `_scan_running_apps`: the `ss -tn state
    established "sport = :N"` liveness probe (`_port_active_conns`), and
    the `systemctl stop streamlit-app@<name>.service` that `cmd_app_stop`
    issues when a candidate is actually stopped. `_ps_lines` itself never
    reaches this binary — it is short-circuited by
    SECUBOX_STREAMLIT_PS_SOURCE.

    `established_ports`: ports that must be reported as having a live
    ESTABLISHED connection (the app is "active", never a stop candidate).
    """
    ports_csv = ",".join(str(p) for p in established_ports)
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2  # drop -n <name>
shift    # drop --
if [ "$1" = "ss" ]; then
    port=$(printf '%s' "$5" | grep -oE '[0-9]+$')
    printf 'State      Recv-Q Send-Q Local Address:Port   Peer Address:Port\\n'
    case ",{ports}," in
        *",$port,"*)
            printf 'ESTAB      0      0      10.20.30.40:%s      10.20.30.1:54321\\n' "$port"
            ;;
    esac
    exit 0
fi
if [ "$1" = "systemctl" ]; then
    printf '%s\\n' "$*" >> "{stop_log}"
    exit 0
fi
exit 0
""".format(ports=ports_csv, stop_log=stop_log))


def _env(apps_dir, conf, idle_dir, ps_file, extra_path):
    return {
        "PATH": "{}:/usr/bin:/bin:/usr/sbin:/sbin".format(extra_path),
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
        "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_file),
    }


def _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file, extra_args=()):
    env = _env(apps_dir, conf, idle_dir, ps_file, str(tmp_path))
    argv = ["bash", str(CTL), "app", "idle-check", *extra_args]
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30)


def _age_state_file(idle_dir: Path, name: str, seconds_ago: int) -> Path:
    idle_dir.mkdir(parents=True, exist_ok=True)
    f = idle_dir / f"{name}.state"
    f.write_text("")
    ts = time.time() - seconds_ago
    os.utime(f, (ts, ts))
    return f


def test_idle_check_sees_flat_script_apps_with_no_port_file(tmp_path):
    """THE bug (#958 follow-up): two flat-script apps, both genuinely
    running per real ps output, neither with a .streamlit.toml anywhere
    (reproduces the board reality of processes never started via `app
    start`/`app wake`). Both are long past the idle timeout. Before the
    fix this reports active=0 idle=0 stopped=0 no matter what — the
    directory-only glob never even looks at flat scripts, and even a
    directory app without a port file would be invisible to the old
    `_app_running` check. After the fix both must be recognized as
    running and stopped for real inactivity.
    """
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "alpha.py").write_text("import streamlit\n")
    (apps_dir / "beta.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\nenabled = true\ntimeout_minutes = 1\n")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text(
        "streamlit run alpha.py --server.port=8601 --server.address 0.0.0.0\n"
        "streamlit run beta.py --server.port=8602 --server.address 0.0.0.0\n"
    )
    stop_log = tmp_path / "stop.log"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, stop_log, established_ports=())
    # Both apps idle well past the 1-minute timeout.
    _age_state_file(idle_dir, "alpha", seconds_ago=3600)
    _age_state_file(idle_dir, "beta", seconds_ago=3600)

    r = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "active=0 idle=0 stopped=2" in r.stdout, r.stdout
    assert "idle-stop: alpha" in r.stdout
    assert "idle-stop: beta" in r.stdout


def test_active_app_with_established_connection_is_never_stopped(tmp_path):
    """An app with a live ESTABLISHED connection must never be a stop
    candidate, even if its recorded last-active timestamp is ancient."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "busy.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\nenabled = true\ntimeout_minutes = 1\n")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run busy.py --server.port=8611\n")
    stop_log = tmp_path / "stop.log"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, stop_log, established_ports=(8611,))
    _age_state_file(idle_dir, "busy", seconds_ago=999999)

    r = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "idle-stop: busy" not in r.stdout
    assert not stop_log.exists() or "busy" not in stop_log.read_text()
    assert "active=1" in r.stdout


def test_missing_timestamp_grants_grace_not_immediate_stop(tmp_path):
    """An app running for the first time idle-check ever sees it (no
    IDLE_STATE_DIR file at all) must NOT be stopped on this very first
    pass — treating "no data" as "idle forever" would kill apps the
    instant idle-check starts tracking them."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "fresh.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"  # deliberately not pre-populated
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\nenabled = true\ntimeout_minutes = 1\n")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run fresh.py --server.port=8621\n")
    stop_log = tmp_path / "stop.log"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, stop_log, established_ports=())

    r = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "idle-stop: fresh" not in r.stdout
    assert not stop_log.exists() or "fresh" not in stop_log.read_text()
    # A state file must now exist so subsequent runs have a real baseline.
    assert (idle_dir / "fresh.state").exists()


def test_future_timestamp_grants_grace_not_immediate_stop(tmp_path):
    """A corrupted/clock-skewed state file whose mtime is in the future
    must not be treated as "idle forever" (a naive `now - last` would go
    negative, but nothing should rely on that being incidentally safe)."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "skewed.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\nenabled = true\ntimeout_minutes = 1\n")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run skewed.py --server.port=8631\n")
    stop_log = tmp_path / "stop.log"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, stop_log, established_ports=())
    _age_state_file(idle_dir, "skewed", seconds_ago=-3600)  # 1h in the future

    r = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "idle-stop: skewed" not in r.stdout
    assert not stop_log.exists() or "skewed" not in stop_log.read_text()
    # The grace period must refresh the timestamp back to "now", not leave
    # the bogus future value in place forever.
    new_mtime = (idle_dir / "skewed.state").stat().st_mtime
    assert abs(new_mtime - time.time()) < 30


def test_dry_run_lists_candidate_without_stopping_or_mutating_state(tmp_path):
    """--dry-run must report what would be stopped without ever calling
    cmd_app_stop, and without touching the idle-state timestamp — so a
    real run right afterwards makes the exact same decision."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "candidate.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\nenabled = true\ntimeout_minutes = 1\n")
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run candidate.py --server.port=8641\n")
    stop_log = tmp_path / "stop.log"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, stop_log, established_ports=())
    state_file = _age_state_file(idle_dir, "candidate", seconds_ago=3600)
    mtime_before = state_file.stat().st_mtime

    r = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file,
                         extra_args=("--dry-run",))

    assert r.returncode == 0, r.stdout + r.stderr
    assert "would stop" in r.stdout and "candidate" in r.stdout, r.stdout
    assert "idle-stop: candidate" not in r.stdout
    assert not stop_log.exists() or "candidate" not in stop_log.read_text()
    assert state_file.stat().st_mtime == mtime_before

    # A real run right after must still find the exact same idle app and
    # actually stop it this time — dry-run must not have consumed or
    # altered the decision.
    r2 = _run_idle_check(tmp_path, apps_dir, conf, idle_dir, ps_file)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert "idle-stop: candidate" in r2.stdout
    assert "candidate" in stop_log.read_text()

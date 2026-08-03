"""Tests for `lxc/streamlit-launch` (structural fix, per-app systemd units).

This is the ExecStart target of `lxc/streamlit-app@.service`, run INSIDE
the streamlit LXC container by systemd, one process per app instance. It
replaces the monolithic `streamlit-all.service` (Type=forking, MainPID
lost to 0, `ExecStop=pkill -f streamlit` killing the entire fleet whenever
any single app was stopped, `enabled` so every app started on every boot).

Deliberately does not re-derive the entrypoint/port itself: it reads the
per-app `.streamlit.toml` streamlitctl already writes (same file, same
format `_app_port_file`/`cmd_app_start` use on the host side) — a second,
independently-written resolution algorithm is exactly the bug class this
project already hit twice (#958, #959).
"""
import stat
import subprocess
from pathlib import Path

LAUNCH = Path(__file__).resolve().parents[2] / "lxc" / "streamlit-launch"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_streamlit(tmp_path: Path, capture: Path) -> None:
    """Stands in for the real `streamlit` binary: records its argv and
    exits immediately instead of actually serving (this script `exec`s
    into it, so nothing else runs afterwards)."""
    _write_exec(tmp_path / "streamlit", """#!/bin/bash
printf '%s\\n' "$*" >> "{capture}"
exit 0
""".format(capture=capture))


def _mock_ss_nothing_listening(tmp_path: Path) -> None:
    _write_exec(tmp_path / "ss", """#!/bin/bash
printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n'
exit 0
""")


def _mock_ss_port_taken(tmp_path: Path, taken_port: int) -> None:
    _write_exec(tmp_path / "ss", """#!/bin/bash
printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n'
printf 'LISTEN 0      128    0.0.0.0:{port}          0.0.0.0:*\\n'
exit 0
""".format(port=taken_port))


def _env(apps_dir, extra_path):
    return {
        "PATH": "{}:/usr/bin:/bin:/usr/sbin:/sbin".format(extra_path),
        "STREAMLIT_APPS_PATH": str(apps_dir),
    }


def _run(name, apps_dir, tmp_path, extra_env=None):
    env = _env(apps_dir, str(tmp_path))
    if extra_env:
        env.update(extra_env)
    return subprocess.run(["bash", str(LAUNCH), name], capture_output=True,
                           text=True, env=env, timeout=30)


def test_flat_script_app_execs_streamlit_with_its_recorded_port(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "billets.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-billets.toml").write_text(
        'port = 8501\nentrypoint = "billets.py"\n'
    )
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("billets", apps_dir, tmp_path)

    assert r.returncode == 0, r.stderr
    launched = capture.read_text()
    assert "run billets.py" in launched
    assert "--server.port=8501" in launched
    assert "--server.headless=true" in launched


def test_directory_app_execs_streamlit_with_its_recorded_entrypoint(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "control"; d.mkdir()
    (d / "test_dashboard.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text(
        'port = 8600\nentrypoint = "control/test_dashboard.py"\n'
    )
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("control", apps_dir, tmp_path)

    assert r.returncode == 0, r.stderr
    launched = capture.read_text()
    assert "run control/test_dashboard.py" in launched
    assert "--server.port=8600" in launched


def test_refuses_when_no_config_file_exists_at_all(tmp_path):
    """An app that was never started via streamlitctl has no
    .streamlit.toml — the launcher must refuse rather than guess a port
    (never a repeat of the old silent-default-8501 behavior)."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "ghost.py").write_text("import streamlit\n")
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("ghost", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists(), "streamlit must never have been invoked"
    assert "refus" in r.stderr.lower()


def test_refuses_when_port_is_missing_from_config(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "noport.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-noport.toml").write_text('entrypoint = "noport.py"\n')
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("noport", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists()
    assert "port" in r.stderr.lower()


def test_refuses_when_port_is_zero(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "zeroport.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-zeroport.toml").write_text(
        'port = 0\nentrypoint = "zeroport.py"\n'
    )
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("zeroport", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists()


def test_refuses_when_entrypoint_is_missing_from_config(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "noep.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-noep.toml").write_text('port = 8502\n')
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("noep", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists()
    assert "entrypoint" in r.stderr.lower()


def test_refuses_when_recorded_entrypoint_no_longer_exists_on_disk(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / ".streamlit-vanished.toml").write_text(
        'port = 8503\nentrypoint = "vanished.py"\n'
    )
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_nothing_listening(tmp_path)

    r = _run("vanished", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists()


def test_refuses_when_the_port_is_already_in_use_by_something_else(tmp_path):
    """Two apps sharing a declared port (5 of them do, on the board) must
    never both end up bound — the second one to start must fail loudly,
    never silently steal or share the socket."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "second.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-second.toml").write_text(
        'port = 8501\nentrypoint = "second.py"\n'
    )
    capture = tmp_path / "captured.txt"
    _mock_streamlit(tmp_path, capture)
    _mock_ss_port_taken(tmp_path, 8501)

    r = _run("second", apps_dir, tmp_path)

    assert r.returncode != 0
    assert not capture.exists(), "must never start on a port owned by another app"
    assert "conflict" in r.stderr.lower() or "already in use" in r.stderr.lower()

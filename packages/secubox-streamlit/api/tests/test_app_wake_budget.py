"""Tests for `streamlitctl app wake`'s wait budget (ref #958).

Board reality: with average load at 45-90, a wake commonly takes 26 to 78s
(sometimes more) before the app's port starts listening. `cmd_app_wake`
used to fall back to a hardcoded 30s whenever the caller omitted the
optional 3rd CLI argument (`app wake <name> [seconds]`) — the exact case
of the capture-pass script that triggered #958, which never passes that
argument. 30s is below the *low* end of the observed range, so the wake
gave up before the app was ready essentially every time the board was
under any load.

The fix keeps the existing CLI argument as the highest-priority override
(a caller that knows better always wins) and replaces the bare "30"
fallback with a `[wake] budget_seconds` key in $CONF_PATH, defaulting to a
much more realistic value when the key (or the file) is absent.

These tests pin the wait budget actually used by inspecting the "will
wait up to Ns" log line `cmd_app_wake` prints right after resolving it —
the app is made to answer "listening" on the very first poll in every
case here, so no test actually blocks on the wait loop; only the budget
*computation* is under test. Wait-loop mechanics (does it genuinely keep
polling instead of some independent inner cap) are exercised by
test_app_start_wake.py, unchanged by this fix.
"""
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path) -> None:
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
echo "State: RUNNING"
exit 0
""")


def _mock_lxc_attach_instant(tmp_path: Path) -> None:
    """The app is reported listening from the very first poll — the wake
    loop runs at most one iteration in every test here, so none of them
    are slowed down by the budget under test."""
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2  # drop -n <name>
shift    # drop --
if [ "$1" = "systemctl" ]; then
    exit 0
fi
if [ "$1" = "ss" ]; then
    port=$(printf '%s' "$3" | grep -oE '[0-9]+$')
    printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n'
    printf 'LISTEN 0      128    0.0.0.0:%s          0.0.0.0:*\\n' "$port"
    exit 0
fi
exit 0
""")


def _env(apps_dir, conf, idle_dir, extra_path):
    return {
        "PATH": "{}:/usr/bin:/bin:/usr/sbin:/sbin".format(extra_path),
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
    }


def _setup(tmp_path, conf_text):
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    (apps_dir / "cc_osint.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    # `app wake` never takes a port argument — a resolvable port has to
    # come from somewhere else. A declared [apps.cc_osint].port keeps
    # these tests focused purely on the wait-budget computation, never
    # tripping the (unrelated) "no port configured" refusal.
    conf.write_text(conf_text + "\n[apps.cc_osint]\nport = 8501\n")
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach_instant(tmp_path)
    return apps_dir, conf, idle_dir


def _run_wake(name, apps_dir, conf, idle_dir, tmp_path, wait_arg=None):
    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    argv = ["bash", str(CTL), "app", "wake", name]
    if wait_arg is not None:
        argv.append(wait_arg)
    return subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30)


def test_wake_default_budget_is_not_hardcoded_30(tmp_path):
    """No [wake] section at all: the fallback must still be well above
    the old bare "30" — 30s is below the low end of what's observed on a
    loaded board (26-78s), so it must never be the silent default again."""
    apps_dir, conf, idle_dir = _setup(tmp_path, "")

    r = _run_wake("cc_osint", apps_dir, conf, idle_dir, tmp_path)

    assert r.returncode == 0, r.stderr
    assert "will wait up to 30s" not in r.stdout, r.stdout


def test_wake_default_budget_comes_from_wake_config_key(tmp_path):
    """[wake].budget_seconds must be honored as the default when the
    caller omits the 3rd CLI argument entirely (the capture-pass script's
    actual call pattern)."""
    apps_dir, conf, idle_dir = _setup(tmp_path, "[wake]\nbudget_seconds = 45\n")

    r = _run_wake("cc_osint", apps_dir, conf, idle_dir, tmp_path)

    assert r.returncode == 0, r.stderr
    assert "will wait up to 45s" in r.stdout, r.stdout


def test_wake_cli_argument_still_overrides_configured_default(tmp_path):
    """An explicit budget on the command line always wins over the
    configured default — configurability must not remove the existing
    per-call override."""
    apps_dir, conf, idle_dir = _setup(tmp_path, "[wake]\nbudget_seconds = 999\n")

    r = _run_wake("cc_osint", apps_dir, conf, idle_dir, tmp_path, wait_arg="7")

    assert r.returncode == 0, r.stderr
    assert "will wait up to 7s" in r.stdout, r.stdout

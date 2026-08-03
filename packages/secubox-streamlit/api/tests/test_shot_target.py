"""Tests for `streamlitctl app shot-target` (#958).

This verb resolves the capture target (direct container URL + absolute
source path) for ONE app, and is the single place that knows how to reach
a Streamlit app from the host (container IP via `lxc-info`, port from the
persisted `.streamlit.toml`). `api/shots.py` calls it rather than
re-deriving entrypoint/port/IP itself, so it can never diverge the way
app start/wake/audit did before #959.

The test that matters most here is `test_sleeping_app_never_gets_a_url`:
this verb must NEVER hand back a capturable URL for an app that isn't
already running — that's what stops the capturer from ever being able to
wake an app just to photograph it.
"""
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path, ip: str = "10.20.30.40") -> None:
    """Stands in for `lxc-info -n <name> -s` (state check) AND
    `lxc-info -n <name> -i -H` (bare IP, no field label) — both invoked
    with `-n <name>` first, so a single `shift 2` gets to the branch."""
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
shift 2  # drop -n <name>
if [ "$1" = "-s" ]; then
    echo "State: RUNNING"
    exit 0
fi
if [ "$1" = "-i" ]; then
    echo "{ip}"
    exit 0
fi
exit 1
""".format(ip=ip))


def _mock_lxc_attach_listening(tmp_path: Path) -> None:
    """Stands in for `lxc-attach -n <name> -- ss -tln "sport = :N"` and
    always reports the requested port as LISTENing."""
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2  # drop -n <name>
shift    # drop --
if [ "$1" = "ss" ]; then
    port=$(printf '%s' "$3" | grep -oE '[0-9]+$')
    printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n'
    printf 'LISTEN 0      128    0.0.0.0:%s          0.0.0.0:*\\n' "$port"
    exit 0
fi
exit 0
""")


def _env(apps_dir, conf, idle_dir, extra_path=None):
    base = "/usr/bin:/bin:/usr/sbin:/sbin"
    path = "{}:{}".format(extra_path, base) if extra_path else base
    return {
        "PATH": path,
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
    }


def _run_shot_target(name, apps_dir, conf, idle_dir, extra_path=None):
    env = _env(apps_dir, conf, idle_dir, extra_path)
    return subprocess.run(["bash", str(CTL), "app", "shot-target", name],
                           capture_output=True, text=True, env=env, timeout=30)


def test_unknown_app_returns_ok_false(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")

    r = _run_shot_target("ghost", apps_dir, conf, idle_dir)

    assert r.returncode == 2
    assert '"ok":false' in r.stdout
    assert "not found" in r.stdout


def test_sleeping_app_never_gets_a_url(tmp_path):
    """THE invariant this verb exists to hold (#957 §3.5): an app that is
    known (on disk) but not currently running must NEVER get back a
    capturable target — the capturer relies on this to never wake an app
    just to photograph it."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "sleepy.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    _mock_lxc_info(tmp_path)  # container running, but nothing listens

    r = _run_shot_target("sleepy", apps_dir, conf, idle_dir, extra_path=str(tmp_path))

    assert r.returncode == 3
    assert '"ok":false' in r.stdout
    assert "not running" in r.stdout
    assert '"url"' not in r.stdout


def test_running_flat_script_resolves_ip_port_and_source(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "billets.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-billets.toml").write_text("port = 8530\n")
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    _mock_lxc_info(tmp_path, ip="10.20.30.40")
    _mock_lxc_attach_listening(tmp_path)

    r = _run_shot_target("billets", apps_dir, conf, idle_dir, extra_path=str(tmp_path))

    assert r.returncode == 0, r.stdout + r.stderr
    assert '"ok":true' in r.stdout
    assert '"url":"http://10.20.30.40:8530/"' in r.stdout
    assert str(apps_dir / "billets.py") in r.stdout


def test_running_directory_app_source_includes_relative_entrypoint(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    d = apps_dir / "control"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text("port = 8600\n")
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    _mock_lxc_info(tmp_path, ip="10.20.30.41")
    _mock_lxc_attach_listening(tmp_path)

    r = _run_shot_target("control", apps_dir, conf, idle_dir, extra_path=str(tmp_path))

    assert r.returncode == 0, r.stdout + r.stderr
    assert '"url":"http://10.20.30.41:8600/"' in r.stdout
    assert str(d / "app.py") in r.stdout


def test_running_but_lxc_ip_unavailable_reports_error_not_a_url(tmp_path):
    """If the container's IP can't be resolved (e.g. it stopped between
    the running-check and the IP lookup), the verb must fail cleanly,
    never fabricate a URL."""
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    (apps_dir / "flaky.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-flaky.toml").write_text("port = 8540\n")
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")

    # lxc-info reports RUNNING for -s, but returns nothing for -i (no IP).
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
shift 2
if [ "$1" = "-s" ]; then echo "State: RUNNING"; exit 0; fi
exit 0
""")
    _mock_lxc_attach_listening(tmp_path)

    r = _run_shot_target("flaky", apps_dir, conf, idle_dir, extra_path=str(tmp_path))

    assert r.returncode == 5
    assert '"ok":false' in r.stdout
    assert '"url"' not in r.stdout

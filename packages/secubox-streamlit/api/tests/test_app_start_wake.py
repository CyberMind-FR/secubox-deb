"""Tests for `streamlitctl app start` / `app wake` against flat-script apps
and non-conventional directory entrypoints (#959).

Three layers assumed "an app is a directory containing app.py": cmd_app_start,
cmd_app_wake (this file) and the `POST /apps/{name}/wake` API route (see
api/tests/test_idle.py::test_wake_missing_app_returns_404). cmd_app_audit
already resolved both shapes correctly via _detect_entrypoint — these tests
pin the same resolution now shared through the extracted _app_entrypoint
helper, so start/wake never again diverge from what audit already knows.
"""
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path) -> None:
    """`lxc-info -n <name> -s` reports the container as RUNNING."""
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
echo "State: RUNNING"
exit 0
""")


def _mock_lxc_attach(tmp_path: Path, capture_file: Path, started_flag: Path) -> None:
    """Stands in for lxc-attach for both the start invocation (`sh -c ...`)
    and the wake readiness poll (`ss -tln "sport = :N"`).

    Real invocations are `lxc-attach -n <name> -- <cmd...>` — this strips
    the `-n <name> --` prefix and dispatches on what follows. The `sh -c`
    branch records the launched command line (so tests can assert on the
    exact `streamlit run <path>` invoked) and flips a flag; the `ss`
    branch reports the app's port as listening only once that flag is
    set, so `_app_running`'s poll loop genuinely observes "not running,
    then running" across a real start.
    """
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2  # drop -n <name>
shift    # drop --
if [ "$1" = "sh" ]; then
    printf '%s\\n' "$3" >> "{capture}"
    touch "{flag}"
    exit 0
fi
if [ "$1" = "ss" ]; then
    if [ -f "{flag}" ]; then
        port=$(printf '%s' "$3" | grep -oE '[0-9]+$')
        printf 'State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\\n'
        printf 'LISTEN 0      128    0.0.0.0:%s          0.0.0.0:*\\n' "$port"
    fi
    exit 0
fi
exit 0
""".format(capture=capture_file, flag=started_flag))


def _env(apps_dir, conf, idle_dir, extra_path=None):
    base = "/usr/bin:/bin:/usr/sbin:/sbin"
    path = "{}:{}".format(extra_path, base) if extra_path else base
    return {
        "PATH": path,
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
    }


def test_wake_flat_script_succeeds(tmp_path):
    """A flat .py script under APPS_PATH is a valid app: wake must bring it
    up, not bounce with "app not found" (pre-#959 required a directory —
    12 of the 15 apps online on the board are flat scripts)."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    (apps_dir / "billets.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")

    capture = tmp_path / "captured_cmd.txt"
    flag = tmp_path / "started.flag"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, capture, flag)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "wake", "billets", "5"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "not found" not in r.stderr.lower()
    assert flag.exists(), "streamlit run was never invoked: " + r.stderr

    launched = capture.read_text()
    assert "streamlit run billets.py" in launched
    assert "cd /srv/streamlit/apps" in launched
    assert "cd /srv/apps/billets" not in launched

    # Port persisted next to the script, never as a phantom "billets/" dir
    # sharing the script's own name — that would show up as a duplicate,
    # entrypoint-less disk entry in `app audit`/`app list`.
    assert not (apps_dir / "billets").exists()
    port_file = apps_dir / ".streamlit-billets.toml"
    assert port_file.exists()
    assert "port = 8501" in port_file.read_text()


def test_start_directory_app_with_non_conventional_entrypoint_succeeds(tmp_path):
    """A directory app whose entrypoint isn't literally app.py/main.py/
    streamlit_app.py (e.g. control/test_dashboard.py on the board) must
    still start — cmd_app_start used to only ever look for those three
    conventional names."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    d = apps_dir / "control"
    d.mkdir()
    (d / "test_dashboard.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")

    capture = tmp_path / "captured_cmd.txt"
    flag = tmp_path / "started.flag"
    _mock_lxc_info(tmp_path)
    _mock_lxc_attach(tmp_path, capture, flag)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "start", "control", "8600"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    launched = capture.read_text()
    assert "streamlit run control/test_dashboard.py" in launched
    assert "cd /srv/streamlit/apps" in launched
    assert "cd /srv/apps/control" not in launched

    port_file = d / ".streamlit.toml"
    assert port_file.exists()
    assert "port = 8600" in port_file.read_text()


def test_start_archived_app_is_still_refused(tmp_path):
    """Archived apps must never auto-start (#956) — the entrypoint-based
    existence check introduced by #959 must not bypass this guard."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    d = apps_dir / "oldapp"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[apps.oldapp]\narchived = true\nenabled = false\n")

    env = _env(apps_dir, conf, idle_dir)
    r = subprocess.run(["bash", str(CTL), "app", "start", "oldapp"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode != 0
    assert "archiv" in r.stderr.lower()


def test_start_unknown_app_message_differs_from_no_entrypoint(tmp_path):
    """An app absent from disk entirely must fail with a message distinct
    from a known directory whose entrypoint can't be resolved — the panel
    needs to tell "unknown app" from "broken app" apart (#959)."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    # Container reachable throughout, so both assertions isolate the
    # entrypoint-resolution outcome rather than an unrelated "container not
    # running" short-circuit.
    _mock_lxc_info(tmp_path)
    env = _env(apps_dir, conf, idle_dir, str(tmp_path))

    r_missing = subprocess.run(["bash", str(CTL), "app", "start", "ghost"],
                                capture_output=True, text=True, env=env, timeout=30)
    assert r_missing.returncode != 0
    assert "not found" in r_missing.stderr.lower()
    assert "entrypoint" not in r_missing.stderr.lower()

    # A directory that exists but has two competing root scripts and no
    # conventional name resolves to "no entrypoint", never "not found".
    d = apps_dir / "ambiguous"
    d.mkdir()
    (d / "one.py").write_text("# a\n")
    (d / "two.py").write_text("# b\n")
    r_ambiguous = subprocess.run(["bash", str(CTL), "app", "start", "ambiguous"],
                                  capture_output=True, text=True, env=env, timeout=30)
    assert r_ambiguous.returncode != 0
    assert "entrypoint" in r_ambiguous.stderr.lower()
    assert "not found" not in r_ambiguous.stderr.lower()


def test_wake_unknown_app_returns_rc2_for_api_404_mapping(tmp_path):
    """POST /apps/{name}/wake maps streamlitctl's rc=2 to HTTP 404 — pin
    the contract at the ctl level (see api/tests/test_idle.py for the API
    side)."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    idle_dir = tmp_path / "idle"
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(apps_dir, conf, idle_dir)

    r = subprocess.run(["bash", str(CTL), "app", "wake", "ghost", "1"],
                        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 2

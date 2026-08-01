import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _run_app_list(tmp_path, apps, idle_files, timeout_minutes=30):
    """Exécute `streamlitctl app list` contre une arborescence factice."""
    apps_dir = tmp_path / "apps"
    idle_dir = tmp_path / "idle"
    apps_dir.mkdir(); idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text(f"[idle]\ntimeout_minutes = {timeout_minutes}\n")
    for name, port in apps.items():
        d = apps_dir / name
        d.mkdir()
        (d / "app.py").write_text("import streamlit\n")
        (d / ".streamlit.toml").write_text(f"port = {port}\n")
    for name, mtime in idle_files.items():
        f = idle_dir / f"{name}.state"
        f.write_text("")
        import os
        os.utime(f, (mtime, mtime))
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
    }
    r = subprocess.run(["bash", str(CTL), "app", "list"],
                       capture_output=True, text=True, env=env, timeout=30)
    return json.loads(r.stdout)


def test_app_list_reports_sleep_timing(tmp_path):
    import time
    now = int(time.time())
    out = _run_app_list(tmp_path, {"demo": 8501}, {"demo": now - 600})
    app = out["apps"][0]
    assert app["name"] == "demo"
    assert app["last_active"] == now - 600
    assert 595 <= app["idle_seconds"] <= 615
    assert app["sleep_after_seconds"] == 1800


def test_never_seen_app_reports_zero_not_absent(tmp_path):
    """Une appli jamais vue doit dire last_active=0, pas omettre le champ."""
    out = _run_app_list(tmp_path, {"neuve": 8502}, {})
    app = out["apps"][0]
    assert app["last_active"] == 0
    assert "idle_seconds" in app


def test_state_is_sleeping_when_port_is_closed(tmp_path):
    out = _run_app_list(tmp_path, {"demo": 8501}, {})
    assert out["apps"][0]["state"] == "sleeping"


def test_json_escapes_app_name_with_double_quote(tmp_path):
    """App name containing double quote must not corrupt JSON."""
    app_name = 'app"with"quotes'
    out = _run_app_list(tmp_path, {app_name: 8502}, {})
    assert len(out["apps"]) == 1
    app = out["apps"][0]
    assert app["name"] == app_name, f"Expected {app_name}, got {app['name']}"


def test_json_escapes_app_name_with_backslash(tmp_path):
    """App name containing backslash must not corrupt JSON."""
    app_name = r'app\with\backslash'
    out = _run_app_list(tmp_path, {app_name: 8503}, {})
    assert len(out["apps"]) == 1
    app = out["apps"][0]
    assert app["name"] == app_name, f"Expected {app_name}, got {app['name']}"


def test_uses_app_running_function_not_ss(tmp_path):
    """cmd_app_list must call _app_running(), not use ss -tln directly.

    This test verifies the detection happens INSIDE the LXC (via _app_running),
    not on the host (via ss). We mock _app_running to control its verdict.
    """
    apps_dir = tmp_path / "apps"
    idle_dir = tmp_path / "idle"
    apps_dir.mkdir()
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\ntimeout_minutes = 30\n")

    # Create app 'demo' with port 8501
    demo_dir = apps_dir / "demo"
    demo_dir.mkdir()
    (demo_dir / "app.py").write_text("import streamlit\n")
    (demo_dir / ".streamlit.toml").write_text("port = 8501\n")

    # Create a bash wrapper that mocks _app_running to always return "running"
    ctl_wrapper = tmp_path / "streamlitctl_wrapper.sh"
    ctl_path = str(CTL)
    wrapper_script = """#!/bin/bash
set -e

# Source the real streamlitctl
source {ctl}

# Mock _app_running to return 0 (running) for app "demo"
_app_running() {{
    local name="$1"
    if [ "$name" = "demo" ]; then
        return 0  # running
    fi
    return 1  # not running
}}

# Now run the list command
cmd_app_list
""".format(ctl=ctl_path)

    ctl_wrapper.write_text(wrapper_script)
    ctl_wrapper.chmod(0o755)

    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
    }

    r = subprocess.run(["bash", str(ctl_wrapper)],
                       capture_output=True, text=True, env=env, timeout=30)

    # The sourced script outputs a banner, so extract just the JSON
    # (JSON always starts with { and ends with })
    output = r.stdout
    json_start = output.find('{"apps"')
    assert json_start >= 0, f"JSON not found in output: {output}"
    json_part = output[json_start:]

    out = json.loads(json_part)

    # The mock returned 0 (running), so running should be true
    app = out["apps"][0]
    assert app["name"] == "demo"
    assert app["running"] is True, "running must be true (via mocked _app_running returning 0)"
    assert app["state"] == "running", "state must be 'running' (consistent with running=true)"

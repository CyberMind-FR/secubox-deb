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


def test_uses_ps_lines_for_detection(tmp_path):
    """cmd_app_list must use _ps_lines() for efficient detection inside LXC.

    This test verifies the detection happens via _ps_lines() (one lxc-attach call),
    not by calling _app_running for each app. We mock _ps_lines to provide a
    process output showing app "demo" is running.
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

    # Create a bash wrapper that mocks _ps_lines to return "demo" as running
    ctl_wrapper = tmp_path / "streamlitctl_wrapper.sh"
    ctl_path = str(CTL)
    ps_source_file = tmp_path / "ps_source.txt"
    # Format: streamlit run <script_path>
    ps_source_file.write_text("streamlit run /srv/apps/demo/app.py\n")

    wrapper_script = """#!/bin/bash
set -e

# Source the real streamlitctl
source {ctl}

# Now run the list command with injected PS_SOURCE
SECUBOX_STREAMLIT_PS_SOURCE="{ps_source}" cmd_app_list
""".format(ctl=ctl_path, ps_source=ps_source_file)

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

    # _ps_lines provided "demo" as running, so running should be true
    app = out["apps"][0]
    assert app["name"] == "demo"
    assert app["running"] is True, "running must be true (via _ps_lines returning demo process)"
    assert app["state"] == "running", "state must be 'running' (consistent with running=true)"


def test_lxc_attach_called_only_once_for_many_apps(tmp_path):
    """cmd_app_list must call lxc-attach only ONCE, even with many apps.

    This test creates 3+ apps and verifies that lxc-attach is invoked only
    once (via _ps_lines), not once-per-app. We wrap lxc-attach to count calls.
    """
    apps_dir = tmp_path / "apps"
    idle_dir = tmp_path / "idle"
    apps_dir.mkdir()
    idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[idle]\ntimeout_minutes = 30\n")

    # Create 3 apps
    for i, app_name in enumerate(["app1", "app2", "app3"], start=1):
        app_dir = apps_dir / app_name
        app_dir.mkdir()
        (app_dir / "app.py").write_text("import streamlit\n")
        (app_dir / ".streamlit.toml").write_text(f"port = {8500 + i}\n")

    # Create a mock lxc-attach that counts invocations
    lxc_attach_mock = tmp_path / "lxc-attach"
    lxc_attach_mock.write_text("""#!/bin/bash
# Count each invocation
call_file="{call_count_file}"
mkdir -p "$(dirname "$call_file")"
count=$(cat "$call_file" 2>/dev/null || echo 0)
count=$((count + 1))
echo "$count" > "$call_file"

# Return empty ps output (no apps running)
exit 0
""".format(call_count_file=tmp_path / "lxc_attach_calls.txt"))
    lxc_attach_mock.chmod(0o755)

    # Create wrapper script with custom PATH
    ctl_wrapper = tmp_path / "streamlitctl_wrapper.sh"
    ctl_path = str(CTL)
    wrapper_script = """#!/bin/bash
set -e

# Create a mock ps that returns empty (no running apps)
ps_mock="{tmp_dir}/ps"
mkdir -p "$(dirname "$ps_mock")"
cat > "$ps_mock" << 'PSMOCK'
#!/bin/bash
# Simulate ps output with no running streamlit apps
exit 0
PSMOCK
chmod +x "$ps_mock"

# Point to our mock lxc-attach and ps in the PATH
export PATH="{tmp_dir}:$PATH"

# Also inject a mock _ps_lines that uses our fake lxc-attach
source {ctl}

# Override _ps_lines to use the mocked lxc-attach
_ps_lines() {{
    if [ -n "${{SECUBOX_STREAMLIT_PS_SOURCE:-}}" ]; then
        cat "$SECUBOX_STREAMLIT_PS_SOURCE" 2>/dev/null
        return
    fi
    lxc-attach -n "$LXC_NAME" -- \\
        ps -eo args 2>/dev/null | grep "streamlit run" | grep -v grep
}}

# Now run the list command
cmd_app_list
""".format(tmp_dir=tmp_path, ctl=ctl_path)

    ctl_wrapper.write_text(wrapper_script)
    ctl_wrapper.chmod(0o755)

    env = {
        "PATH": str(tmp_path) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
    }

    r = subprocess.run(["bash", str(ctl_wrapper)],
                       capture_output=True, text=True, env=env, timeout=30)

    # Extract JSON
    output = r.stdout
    json_start = output.find('{"apps"')
    assert json_start >= 0, f"JSON not found in output: {output}"

    # Count lxc-attach invocations
    call_count_file = tmp_path / "lxc_attach_calls.txt"
    if call_count_file.exists():
        call_count = int(call_count_file.read_text().strip())
    else:
        call_count = 0

    # With _ps_lines optimization, lxc-attach should be called only once
    # (or not at all if no apps are running in the mock)
    assert call_count <= 1, f"lxc-attach was called {call_count} times, expected <= 1"

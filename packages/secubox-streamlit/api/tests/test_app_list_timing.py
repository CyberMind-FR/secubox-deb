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

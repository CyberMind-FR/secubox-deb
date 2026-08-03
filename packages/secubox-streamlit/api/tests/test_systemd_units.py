"""Tests for the per-app systemd unit structural fix.

Board measurement: `streamlit-all.service` (Type=forking, ExecStart runs
`start-all.sh`) reports `active` with `MainPID=0` — systemd lost track of
the real process the moment it forked. Stopping any single app makes
systemd judge the WHOLE service failed and relaunch every app in the
fleet (`NRestarts=3`, matching three manual shutdown attempts). Being
`enabled` means every app starts on every boot, used or not. None of this
is fixable while one unit owns the entire fleet — hence one
`streamlit-app@<name>.service` instance per app (lxc/streamlit-app@.service),
piloted by streamlitctl instead of a detached `nohup`.

This file pins:
  - `streamlitctl app start/stop/wake` drive the per-app systemd unit
    (`systemctl start/stop streamlit-app@<name>.service`), never a
    detached `nohup streamlit run ...`.
  - An app with no resolvable port refuses to start — never a silent
    default port (the old bare `${2:-8501}` is exactly how 5 apps ended
    up sharing port 8501 on the board).
  - Two apps that would collide on the same port never both get to run:
    the second one to start is refused explicitly.
  - The shipped unit template's restart policy is Restart=no (see
    lxc/streamlit-app@.service for the full reasoning) — a unit that
    restarts itself on its own would reproduce the exact defect being
    fixed.
  - `autostart = true` in [apps.<name>] is the declarative "always on"
    flag: it drives `systemctl enable` for that instance (boot
    persistence) and exempts the app from idle-check's stop decision.
    Nothing starts the whole fleet in bulk by default.
"""
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"
UNIT_FILE = Path(__file__).resolve().parents[2] / "lxc" / "streamlit-app@.service"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _mock_lxc_info(tmp_path: Path) -> None:
    _write_exec(tmp_path / "lxc-info", """#!/bin/bash
echo "State: RUNNING"
exit 0
""")


def _mock_lxc_attach_capture(tmp_path: Path, capture: Path) -> None:
    """Records every `lxc-attach -n <name> -- <cmd...>` invocation's
    trailing command (post `-n <name> --`) as one line, so tests can
    assert exactly what streamlitctl asked systemd to do."""
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2  # drop -n <name>
shift    # drop --
printf '%s\\n' "$*" >> "{capture}"
exit 0
""".format(capture=capture))


def _env(apps_dir, conf, idle_dir, extra_path, ps_file=None):
    e = {
        "PATH": "{}:/usr/bin:/bin:/usr/sbin:/sbin".format(extra_path),
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle_dir),
    }
    if ps_file is not None:
        e["SECUBOX_STREAMLIT_PS_SOURCE"] = str(ps_file)
    return e


def _setup(tmp_path):
    apps_dir = tmp_path / "apps"; apps_dir.mkdir()
    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    return apps_dir, idle_dir, conf


# ─────────────────────────────────────────────────────────────────────
# streamlitctl drives the per-app unit, never a detached nohup
# ─────────────────────────────────────────────────────────────────────

def test_app_start_drives_the_per_app_systemd_unit(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "billets.py").write_text("import streamlit\n")
    conf.write_text('[apps.billets]\nport = 8501\n')
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "start", "billets"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    captured = capture.read_text()
    assert "systemctl start streamlit-app@billets.service" in captured, captured
    assert "nohup" not in captured
    assert "streamlit run" not in captured, (
        "streamlitctl must never invoke `streamlit run` itself — that is "
        "streamlit-launch's job, run BY the unit"
    )


def test_app_stop_drives_the_per_app_systemd_unit(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "stop", "billets"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    captured = capture.read_text()
    assert "systemctl stop streamlit-app@billets.service" in captured, captured
    assert "pkill" not in captured


# ─────────────────────────────────────────────────────────────────────
# No port -> explicit refusal, never a silent default
# ─────────────────────────────────────────────────────────────────────

def test_app_with_no_port_anywhere_refuses_to_start(tmp_path):
    """Neither a persisted .streamlit.toml, nor a declared [apps.*].port,
    nor an explicit CLI argument: this app must refuse outright. The old
    behavior (`local port="${2:-8501}"`) silently picked 8501 — exactly
    how 5 apps ended up sharing that port on the board."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "noport.py").write_text("import streamlit\n")
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "start", "noport"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode != 0
    assert "port" in r.stderr.lower()
    assert not capture.exists(), "must never reach systemctl without a real port"


def test_app_with_persisted_port_file_starts_without_needing_a_cli_argument(tmp_path):
    """A port recorded by a previous `app start`/`app repair --apply` is
    honored automatically — the whole point of persisting it."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "billets.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-billets.toml").write_text(
        'port = 8517\nentrypoint = "billets.py"\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "start", "billets"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "streamlit-app@billets.service" in capture.read_text()


# ─────────────────────────────────────────────────────────────────────
# Port conflict -> explicit refusal, never a silent double-bind
# ─────────────────────────────────────────────────────────────────────

def test_starting_an_app_on_a_port_owned_by_another_running_app_is_refused(tmp_path):
    """5 apps share port 8501 on the board. Whichever of them is already
    running must not be joined by a second one on the same port."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "second.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-second.toml").write_text(
        'port = 8501\nentrypoint = "second.py"\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)
    # `first` is already running on 8501, per the real process table.
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run first.py --server.port=8501\n")

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps_file)
    r = subprocess.run(["bash", str(CTL), "app", "start", "second"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode != 0
    assert "8501" in r.stderr
    assert not capture.exists(), "must never call systemctl start on a conflicting port"


def test_starting_an_app_whose_own_port_is_free_is_unaffected_by_an_unrelated_conflict(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "solo.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-solo.toml").write_text(
        'port = 8777\nentrypoint = "solo.py"\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run unrelated.py --server.port=8501\n")

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps_file)
    r = subprocess.run(["bash", str(CTL), "app", "start", "solo"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "streamlit-app@solo.service" in capture.read_text()


def test_restarting_the_same_app_already_on_its_own_port_is_not_a_conflict(tmp_path):
    """An app is never considered "in conflict with itself" — restarting
    an already-running app on its own persisted port must proceed."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "self.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-self.toml").write_text(
        'port = 8501\nentrypoint = "self.py"\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run self.py --server.port=8501\n")

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps_file)
    r = subprocess.run(["bash", str(CTL), "app", "start", "self"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "streamlit-app@self.service" in capture.read_text()


# ─────────────────────────────────────────────────────────────────────
# Unit template: restart policy
# ─────────────────────────────────────────────────────────────────────

def test_shipped_unit_never_restarts_itself():
    """The central requirement: a stopped app stays stopped. Restart=no
    makes that true unconditionally (see the unit file's own header
    comment for why on-failure was rejected too)."""
    assert UNIT_FILE.exists(), "lxc/streamlit-app@.service must exist"
    text = UNIT_FILE.read_text()
    assert "Restart=no" in text
    for bad in ("Restart=always", "Restart=on-failure", "Restart=on-abnormal"):
        assert bad not in text


def test_shipped_unit_is_not_wanted_by_default_for_every_instance():
    """WantedBy exists (so an operator CAN `systemctl enable` a specific
    instance for boot persistence) but nothing in the unit itself, nor in
    packaging, bulk-enables every instance — that would resurrect
    "every app starts on every boot"."""
    assert UNIT_FILE.exists()
    text = UNIT_FILE.read_text()
    assert "WantedBy=multi-user.target" in text
    postinst = Path(__file__).resolve().parents[2] / "debian" / "postinst"
    assert "streamlit-app@" not in postinst.read_text(), (
        "postinst must never bulk-enable/start the streamlit-app@ template"
    )


# ─────────────────────────────────────────────────────────────────────
# Declarative "always on": [apps.<name>].autostart
# ─────────────────────────────────────────────────────────────────────

def test_autostart_true_enables_the_unit_for_boot_persistence(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "important"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text(
        '[apps.important]\nname = "important"\npath = "important/app.py"\n'
        'autostart = true\nport = 8710\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "autostart"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    captured = capture.read_text()
    assert "systemctl enable streamlit-app@important.service" in captured, captured


def test_autostart_false_never_enables_the_unit(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "occasional"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text(
        '[apps.occasional]\nname = "occasional"\npath = "occasional/app.py"\n'
        'port = 8711\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "autostart"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    captured = capture.read_text() if capture.exists() else ""
    assert "enable streamlit-app@occasional" not in captured


def test_idle_check_never_stops_an_autostart_declared_app(tmp_path):
    """The declarative "always on" flag also exempts the app from
    idle-check — otherwise a pinned app would still be silently put to
    sleep by the timer and, with Restart=no, never come back on its own."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "pinned.py").write_text("import streamlit\n")
    conf.write_text(
        '[idle]\nenabled = true\ntimeout_minutes = 1\n\n'
        '[apps.pinned]\nname = "pinned"\nautostart = true\nport = 8720\n'
    )
    ps_file = tmp_path / "ps.txt"
    ps_file.write_text("streamlit run pinned.py --server.port=8720\n")
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    # Idle for a very long time — would normally be stopped.
    import os
    import time
    idle_dir.mkdir(exist_ok=True)
    f = idle_dir / "pinned.state"
    f.write_text("")
    ts = time.time() - 999999
    os.utime(f, (ts, ts))

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps_file)
    r = subprocess.run(["bash", str(CTL), "app", "idle-check"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "idle-stop: pinned" not in r.stdout
    assert "active=1" in r.stdout, r.stdout


# ─────────────────────────────────────────────────────────────────────
# `app autostart <name> <on|off>` — the operator-facing declarative toggle
# ─────────────────────────────────────────────────────────────────────

def test_autostart_on_with_apply_sets_the_flag_and_enables_the_unit(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "important"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text(
        '[apps.important]\nname = "important"\npath = "important/app.py"\nport = 8710\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "autostart", "important", "on", "--apply"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "autostart = true" in conf.read_text()
    assert "systemctl enable streamlit-app@important.service" in capture.read_text()


def test_autostart_on_without_a_port_is_refused(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "noport"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text('[apps.noport]\nname = "noport"\npath = "noport/app.py"\n')
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "autostart", "noport", "on", "--apply"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    import json
    body = json.loads(r.stdout)
    assert body["actions"][0]["blocked"] is True
    assert body["actions"][0]["applied"] is False
    assert "autostart = true" not in conf.read_text()
    assert not capture.exists()


def test_autostart_off_with_apply_clears_the_flag_and_disables_the_unit(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "important"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text(
        '[apps.important]\nname = "important"\npath = "important/app.py"\n'
        'autostart = true\nport = 8710\n'
    )
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "autostart", "important", "off", "--apply"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert "autostart = false" in conf.read_text()
    assert "systemctl disable streamlit-app@important.service" in capture.read_text()


def test_autostart_dry_run_writes_nothing(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    d = apps_dir / "important"; d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf.write_text(
        '[apps.important]\nname = "important"\npath = "important/app.py"\nport = 8710\n'
    )
    before = conf.read_text()
    _mock_lxc_info(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc_attach_capture(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = subprocess.run(["bash", str(CTL), "app", "autostart", "important", "on"],
                        capture_output=True, text=True, env=env, timeout=30)

    assert r.returncode == 0, r.stderr
    assert conf.read_text() == before
    assert not capture.exists()

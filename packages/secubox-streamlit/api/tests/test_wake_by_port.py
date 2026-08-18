# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""`app wake-by-port <port>` — the wake verb the on-access path calls (#746).

The public path knows a PORT, never an app name: sbxwaf resolved the visitor's
Host through haproxy-routes.json to `10.100.0.50:<port>`, found nobody
listening, and handed the request to the waker. Asking "wake whatever owns port
P" instead of "wake app X" is deliberate:

  - The visitor's request never contributes an app name. Nothing a third party
    sends can reach `systemctl start` — a caller can only ever solicit the app
    that owns the vhost it asked for.
  - It introduces no fifth notion of "which port belongs to which app". This
    module already carries four ([instances.*], the per-app .streamlit.toml,
    haproxy-routes.json, and the live process table) and paid for that twice
    (#958, #959). Resolution here reads the SAME .streamlit.toml that
    streamlit-launch reads and that `app repair` writes.

A port no app claims is refused explicitly rather than woken approximately:
the caller must be able to tell "asleep, come back in a moment" apart from
"nothing here, waiting is pointless" — five vhosts on the board are in that
second state permanently.
"""
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def _mock_lxc(tmp_path: Path, capture: Path) -> None:
    _write_exec(tmp_path / "lxc-info", "#!/bin/bash\necho 'State: RUNNING'\nexit 0\n")
    _write_exec(tmp_path / "lxc-attach", """#!/bin/bash
shift 2
shift
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


def _run(args, env):
    return subprocess.run(["bash", str(CTL)] + args,
                          capture_output=True, text=True, env=env, timeout=60)


def test_wake_by_port_resolves_the_owning_app_and_starts_its_unit(tmp_path):
    """A flat script whose persisted .streamlit.toml claims the port."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "papyrus.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-papyrus.toml").write_text(
        'port = 8525\nentrypoint = "papyrus.py"\n')
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)
    ps = tmp_path / "ps.txt"; ps.write_text("")  # nothing running

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps)
    r = _run(["app", "wake-by-port", "8525", "1"], env)

    captured = capture.read_text() if capture.exists() else ""
    assert "systemctl start streamlit-app@papyrus.service" in captured, (
        f"rc={r.returncode} stdout={r.stdout} stderr={r.stderr} captured={captured}")


def test_wake_by_port_resolves_a_directory_app(tmp_path):
    """The other shape: a directory app keeps its config inside the directory."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "cc_osint").mkdir()
    (apps_dir / "cc_osint" / "app.py").write_text("import streamlit\n")
    (apps_dir / "cc_osint" / ".streamlit.toml").write_text(
        'port = 8527\nentrypoint = "cc_osint/app.py"\n')
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)
    ps = tmp_path / "ps.txt"; ps.write_text("")

    env = _env(apps_dir, conf, idle_dir, str(tmp_path), ps_file=ps)
    r = _run(["app", "wake-by-port", "8527", "1"], env)

    captured = capture.read_text() if capture.exists() else ""
    assert "systemctl start streamlit-app@cc_osint.service" in captured, (
        f"rc={r.returncode} stderr={r.stderr} captured={captured}")


def test_wake_by_port_refuses_a_port_no_app_claims(tmp_path):
    """The five permanently-502 vhosts on the board land here. Refusing with a
    distinct exit code is what lets the caller serve "nothing here" instead of
    a splash page that would never resolve."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "papyrus.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-papyrus.toml").write_text(
        'port = 8525\nentrypoint = "papyrus.py"\n')
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = _run(["app", "wake-by-port", "8506"], env)

    assert r.returncode == 2, (
        f"expected the dedicated 'no owner' code 2, got {r.returncode}: {r.stderr}")
    captured = capture.read_text() if capture.exists() else ""
    assert "systemctl start" not in captured, (
        "an unclaimed port must never start anything: " + captured)


def test_wake_by_port_rejects_a_non_numeric_port(tmp_path):
    """The port reaches this verb from a network-facing path. It is validated
    here rather than trusted — an app name smuggled in as a 'port' must never
    become a systemd instance name."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = _run(["app", "wake-by-port", "papyrus; rm -rf /"], env)

    assert r.returncode != 0
    captured = capture.read_text() if capture.exists() else ""
    assert "systemctl start" not in captured, captured


def test_wake_by_port_check_reports_the_owner_without_starting_it(tmp_path):
    """--check is the question the waker asks BEFORE serving a splash page:
    is there anything here to wait for? It must answer without starting
    anything, and without needing privilege — it only reads files."""
    apps_dir, idle_dir, conf = _setup(tmp_path)
    (apps_dir / "papyrus.py").write_text("import streamlit\n")
    (apps_dir / ".streamlit-papyrus.toml").write_text(
        'port = 8525\nentrypoint = "papyrus.py"\n')
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = _run(["app", "wake-by-port", "8525", "--check"], env)

    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "papyrus", r.stdout
    captured = capture.read_text() if capture.exists() else ""
    assert "systemctl start" not in captured, (
        "--check must never start anything: " + captured)


def test_wake_by_port_check_reports_no_owner_distinctly(tmp_path):
    apps_dir, idle_dir, conf = _setup(tmp_path)
    capture = tmp_path / "captured.txt"
    _mock_lxc(tmp_path, capture)

    env = _env(apps_dir, conf, idle_dir, str(tmp_path))
    r = _run(["app", "wake-by-port", "8506", "--check"], env)

    assert r.returncode == 2, r.returncode

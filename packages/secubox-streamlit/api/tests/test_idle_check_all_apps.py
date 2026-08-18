# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for `streamlitctl app idle-check` (#961).

Three defects had to be fixed together, because each in isolation makes
the platform less safe than before:

  1. The loop only iterated directories (`"$APPS_PATH"/*/`), so the 43
     flat `.py` scripts out of 63 apps on the board could never be put to
     sleep — precisely the apps chronically contributing to the board's
     CPU load, because they had no way to stop.
  2. The port used to decide "is anyone connected" came from a per-app
     `.streamlit.toml` that only exists for 10 of 87 apps on the board
     (written solely by `app start`, itself broken until #959). Port
     absent silently read as "zero connections" — an actively used app
     could be killed. Fixing defect 1 without this one would have put
     the whole fleet to sleep.
  3. The old per-app detection did one `lxc-attach` per app (17s for
     ~60 apps on the board). The fix must not reintroduce that pattern.

Archived apps must stay outside this loop entirely (they don't run, and
stopping one deliberately is `app archive`'s job, never idle-check's).

Ground truth for the "one container call" claim is captured via a
double of `lxc-attach` on PATH (same technique as
test_app_audit.py::test_ps_lines_does_not_pin_lxc_attach_to_a_hardcoded_lxcpath),
counting invocations rather than inspecting argv.
"""
import os
import time
from pathlib import Path

import subprocess

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _backdate(state_file: Path, seconds_ago: int) -> None:
    state_file.touch()
    ts = int(time.time()) - seconds_ago
    os.utime(state_file, (ts, ts))


def _base_env(tmp_path, apps, conf=None, idle=None, ps_source=None, ss_source=None):
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
        "SECUBOX_STREAMLIT_CONF": str(conf or (tmp_path / "streamlit.toml")),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(idle or (tmp_path / "idle")),
    }
    if ps_source is not None:
        env["SECUBOX_STREAMLIT_PS_SOURCE"] = str(ps_source)
    if ss_source is not None:
        env["SECUBOX_STREAMLIT_SS_SOURCE"] = str(ss_source)
    return env


def _run_idle_check(env):
    return subprocess.run(["bash", str(CTL), "app", "idle-check"],
                           capture_output=True, text=True, env=env, timeout=30)


# ─────────────────────────────────────────────────────────────────────────
# Défaut 1 : les scripts à plat entrent dans la boucle
# ─────────────────────────────────────────────────────────────────────────

def test_flat_script_app_enters_idle_loop_and_gets_stopped(tmp_path):
    """A bare .py script (no directory) must be reachable by the idle
    loop and stopped once past its timeout — the pre-#961 loop only
    walked directories and silently skipped it forever."""
    apps = tmp_path / "apps"; apps.mkdir()
    (apps / "flat_app.py").write_text("import streamlit\n")

    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    _backdate(idle_dir / "flat_app.state", 3600)  # older than default 30 min

    ps_source = tmp_path / "ps.txt"
    ps_source.write_text("streamlit run flat_app.py --server.port=8501\n")
    ss_source = tmp_path / "ss.txt"
    ss_source.write_text("")  # no established connections -> genuinely idle

    env = _base_env(tmp_path, apps, idle=idle_dir, ps_source=ps_source, ss_source=ss_source)
    r = _run_idle_check(env)

    assert r.returncode == 0, r.stderr
    out = r.stdout + r.stderr
    assert "idle-stop: flat_app" in out
    assert "stopped=1" in out


# ─────────────────────────────────────────────────────────────────────────
# Applis archivées : jamais touchées
# ─────────────────────────────────────────────────────────────────────────

def test_archived_app_is_never_touched_by_the_idle_loop(tmp_path):
    """An app declared `archived = true` must never be evaluated by the
    idle loop, even if (contrary to convention) a process for it is
    still observed running with zero established connections and a very
    stale state file — its shutdown is `app archive`'s job, never
    automatic.

    A per-app .streamlit.toml AND a working ss/lxc-attach double are
    deliberately provided here (on top of PS_SOURCE/SS_SOURCE) so this
    test exercises the archived-skip specifically — without them, the
    pre-#961 code's own port-file requirement (défaut 2) would ALSO make
    it silently skip this app, passing for the wrong reason and hiding
    the missing archived check entirely."""
    apps = tmp_path / "apps"
    d = apps / "archived_app"; d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text("port = 8501\n")

    conf = tmp_path / "streamlit.toml"
    conf.write_text("[apps.archived_app]\narchived = true\n")

    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    _backdate(idle_dir / "archived_app.state", 3600)

    ps_source = tmp_path / "ps.txt"
    ps_source.write_text("streamlit run archived_app/app.py --server.port=8501\n")
    ss_source = tmp_path / "ss.txt"
    ss_source.write_text("")

    fake_bin = tmp_path / "fakebin"; fake_bin.mkdir()
    fake_lxc_info = fake_bin / "lxc-info"
    fake_lxc_info.write_text("#!/bin/sh\necho RUNNING\nexit 0\n")
    fake_lxc_info.chmod(0o755)
    # Minimal ss simulator so the OLD per-app _app_running/_app_active_conns
    # path (still exercised by the pre-#961 code this test must fail
    # against) sees the app as listening with zero established
    # connections — matching what the PS_SOURCE/SS_SOURCE snapshot says
    # for the fixed code.
    fake_lxc_attach = fake_bin / "lxc-attach"
    fake_lxc_attach.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *"state established"*)\n'
        '    echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"\n'
        "    ;;\n"
        '  *-tln*)\n'
        '    echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"\n'
        '    echo "LISTEN 0 128 0.0.0.0:8501 *:*"\n'
        "    ;;\n"
        "esac\n"
        "exit 0\n"
    )
    fake_lxc_attach.chmod(0o755)

    env = _base_env(tmp_path, apps, conf=conf, idle=idle_dir,
                     ps_source=ps_source, ss_source=ss_source)
    env["PATH"] = f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin"
    r = _run_idle_check(env)

    assert r.returncode == 0, r.stderr
    out = r.stdout + r.stderr
    assert "idle-stop: archived_app" not in out
    assert "active=0 idle=0 stopped=0" in out


# ─────────────────────────────────────────────────────────────────────────
# Défaut 2 : port introuvable -> ne jamais endormir
# ─────────────────────────────────────────────────────────────────────────

def test_running_app_with_undeterminable_port_is_not_stopped(tmp_path):
    """A running app whose real port can't be extracted from its process
    command line (no --server.port flag observed) must be treated as
    ACTIVE, never stopped — "in doubt, don't sleep": getting this wrong
    by leaving it running costs CPU, getting it wrong by killing it costs
    someone's work."""
    apps = tmp_path / "apps"; apps.mkdir()
    (apps / "mystery.py").write_text("import streamlit\n")

    idle_dir = tmp_path / "idle"; idle_dir.mkdir()
    _backdate(idle_dir / "mystery.state", 7200)  # very stale

    ps_source = tmp_path / "ps.txt"
    ps_source.write_text("streamlit run mystery.py\n")  # no port flag at all
    ss_source = tmp_path / "ss.txt"
    ss_source.write_text("")

    env = _base_env(tmp_path, apps, idle=idle_dir, ps_source=ps_source, ss_source=ss_source)
    r = _run_idle_check(env)

    assert r.returncode == 0, r.stderr
    out = r.stdout + r.stderr
    assert "idle-stop: mystery" not in out
    assert "active=1" in out


# ─────────────────────────────────────────────────────────────────────────
# Une seule invocation de conteneur pour toute la boucle
# ─────────────────────────────────────────────────────────────────────────

def test_idle_check_makes_exactly_one_container_call_regardless_of_app_count(tmp_path):
    """The whole idle-check run must invoke the container exactly once,
    no matter how many apps are on disk — a prior version doing one
    lxc-attach per app took 17s for ~60 apps; reintroducing that pattern
    here (e.g. one `ss` call per app to read established connections)
    would have the same effect. Captured via a double of `lxc-attach` on
    PATH that just counts invocations, exercising the REAL (non-mocked)
    code path — SECUBOX_STREAMLIT_PS_SOURCE/SS_SOURCE are deliberately
    NOT set."""
    apps = tmp_path / "apps"; apps.mkdir()
    names = [f"app{i}" for i in range(5)]
    ports = [8501 + i for i in range(len(names))]
    for n in names:
        (apps / f"{n}.py").write_text("import streamlit\n")

    fake_bin = tmp_path / "fakebin"; fake_bin.mkdir()
    call_log = tmp_path / "lxc-attach.calls"
    snapshot_file = tmp_path / "snapshot.txt"

    ps_lines = "\n".join(f"streamlit run {n}.py --server.port={p}"
                          for n, p in zip(names, ports))
    ss_header = "State Recv-Q Send-Q Local Address:Port Peer Address:Port"
    ss_lines = "\n".join(f"ESTAB 0 0 10.0.3.5:{p} 10.0.3.1:{40000 + i}"
                          for i, p in enumerate(ports))
    snapshot_file.write_text(
        "@@SBX-PS@@\n" + ps_lines + "\n@@SBX-SS@@\n" + ss_header + "\n" + ss_lines + "\n"
    )

    fake_lxc_info = fake_bin / "lxc-info"
    fake_lxc_info.write_text("#!/bin/sh\necho RUNNING\nexit 0\n")
    fake_lxc_info.chmod(0o755)

    fake_lxc_attach = fake_bin / "lxc-attach"
    fake_lxc_attach.write_text(
        "#!/bin/sh\n"
        'echo call >> "$LXC_ATTACH_CALL_LOG"\n'
        'cat "$LXC_ATTACH_SNAPSHOT_FILE"\n'
        "exit 0\n"
    )
    fake_lxc_attach.chmod(0o755)

    conf = tmp_path / "streamlit.toml"; conf.write_text("")
    env = {
        "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
        "LXC_ATTACH_CALL_LOG": str(call_log),
        "LXC_ATTACH_SNAPSHOT_FILE": str(snapshot_file),
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
    }
    r = _run_idle_check(env)

    assert r.returncode == 0, r.stderr
    assert call_log.exists(), "lxc-attach was never invoked"
    calls = [line for line in call_log.read_text().splitlines() if line]
    assert len(calls) == 1, f"expected exactly one container call, got {len(calls)}: {calls}"
    # All 5 apps had an established connection in the snapshot: none idle.
    out = r.stdout + r.stderr
    assert "active=5 idle=0 stopped=0" in out

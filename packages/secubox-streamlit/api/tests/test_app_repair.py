# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for `streamlitctl app repair` (#956) — dry-run by default, fixes
config references but never touches app files/directories. All three
scenarios were verified on the board:

  * [apps.test_app] declared in streamlit.toml with no matching disk entry
    (orphan declaration).
  * [apps.wuyun_liuqi] path = "tong_shu_app.py" — a copy-paste duplicate
    of [apps.tong_shu_app]'s own path, while wuyun_liuqi.py exists on
    disk (wrong declared path).
  * a per-app .streamlit.toml with a port that doesn't match the port the
    process is actually listening on (stale port).
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _env(tmp_path, apps_dir=None, conf=None, ps=None):
    apps_dir = apps_dir or (tmp_path / "apps")
    apps_dir.mkdir(exist_ok=True)
    conf_path = conf or (tmp_path / "streamlit.toml")
    if not conf_path.exists():
        conf_path.write_text("")
    ps_path = tmp_path / "ps.txt"
    ps_path.write_text(ps or "")
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf_path),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_path),
    }


def _repair(tmp_path, env, apply=False):
    args = ["bash", str(CTL), "app", "repair"]
    if apply:
        args.append("--apply")
    r = subprocess.run(args, capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def _action(out, app_type, app_name):
    matches = [a for a in out["actions"] if a["type"] == app_type and a["app"] == app_name]
    assert matches, f"no {app_type} action for {app_name} in {out['actions']}"
    return matches[0]


# ─────────────────────────────────────────────────────────────────────
# Case 1: orphan declaration
# ─────────────────────────────────────────────────────────────────────

def test_orphan_declaration_is_proposed_in_dry_run(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n')
    env = _env(tmp_path, conf=conf)
    out = _repair(tmp_path, env, apply=False)
    action = _action(out, "orphan-declaration", "test_app")
    assert action["applied"] is False
    assert out["apply"] is False
    assert out["summary"]["applied"] == 0
    # Simulation mode must not touch the file at all.
    assert conf.read_text() == '[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n'


def test_orphan_declaration_is_removed_with_apply(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.keep_me]\nname = "keep_me"\npath = "keep_me.py"\nenabled = true\n\n'
        '[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n'
    )
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "keep_me.py").write_text("import streamlit\n")
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    out = _repair(tmp_path, env, apply=True)
    action = _action(out, "orphan-declaration", "test_app")
    assert action["applied"] is True

    text = conf.read_text()
    assert "[apps.test_app]" not in text
    assert "[apps.keep_me]" in text  # untouched declared-and-present app survives


def test_orphan_declaration_apply_creates_a_timestamped_backup(tmp_path):
    conf = tmp_path / "streamlit.toml"
    original = '[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n'
    conf.write_text(original)
    env = _env(tmp_path, conf=conf)
    _repair(tmp_path, env, apply=True)
    backups = list(tmp_path.glob("streamlit.toml.bak.*"))
    assert len(backups) == 1, backups
    assert backups[0].read_text() == original


def test_declared_and_running_app_without_disk_entry_is_not_orphan(tmp_path):
    """A declared app currently running (script form, no disk dir) is not
    an orphan even though it has no dir entry."""
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.live_only]\nname = "live_only"\npath = "live_only.py"\nenabled = true\n')
    env = _env(tmp_path, conf=conf, ps="streamlit run live_only.py --server.port 8600\n")
    out = _repair(tmp_path, env, apply=False)
    assert [a for a in out["actions"] if a["app"] == "live_only"] == []


# ─────────────────────────────────────────────────────────────────────
# Case 2: wrong declared path (duplicate copy-paste)
# ─────────────────────────────────────────────────────────────────────

def _wrong_path_conf(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.tong_shu_app]\nname = "tong_shu_app"\npath = "tong_shu_app.py"\nenabled = true\n\n'
        '[apps.wuyun_liuqi]\nname = "wuyun_liuqi"\npath = "tong_shu_app.py"\nenabled = true\n'
    )
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "tong_shu_app.py").write_text("import streamlit\n")
    (apps / "wuyun_liuqi.py").write_text("import streamlit\n")
    return conf, apps


def test_wrong_path_is_proposed_only_for_the_app_whose_own_file_exists(tmp_path):
    conf, apps = _wrong_path_conf(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    out = _repair(tmp_path, env, apply=False)

    wuyun = _action(out, "wrong-path", "wuyun_liuqi")
    assert wuyun["from"] == "tong_shu_app.py"
    assert wuyun["to"] == "wuyun_liuqi.py"
    assert wuyun["applied"] is False

    # tong_shu_app's own declared path is already correct: no action for it.
    assert [a for a in out["actions"] if a["app"] == "tong_shu_app"] == []


def test_wrong_path_dry_run_does_not_modify_the_config(tmp_path):
    conf, apps = _wrong_path_conf(tmp_path)
    before = conf.read_text()
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    _repair(tmp_path, env, apply=False)
    assert conf.read_text() == before
    assert list(tmp_path.glob("streamlit.toml.bak.*")) == []


def test_wrong_path_is_corrected_with_apply(tmp_path):
    conf, apps = _wrong_path_conf(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    out = _repair(tmp_path, env, apply=True)
    wuyun = _action(out, "wrong-path", "wuyun_liuqi")
    assert wuyun["applied"] is True

    text = conf.read_text()
    assert '[apps.wuyun_liuqi]' in text
    section = text.split("[apps.wuyun_liuqi]", 1)[1]
    assert 'path = "wuyun_liuqi.py"' in section
    # The other, already-correct section is untouched.
    assert 'path = "tong_shu_app.py"' in text.split("[apps.tong_shu_app]", 1)[1]


def test_wrong_path_repair_never_deletes_the_disk_files(tmp_path):
    conf, apps = _wrong_path_conf(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    _repair(tmp_path, env, apply=True)
    assert (apps / "tong_shu_app.py").exists()
    assert (apps / "wuyun_liuqi.py").exists()


# ─────────────────────────────────────────────────────────────────────
# Case 3: stale port
# ─────────────────────────────────────────────────────────────────────

def _stale_port_setup(tmp_path, declared_port="8501", real_port="8600"):
    apps = tmp_path / "apps"
    d = apps / "running_app"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text(f"port = {declared_port}\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    ps = f"streamlit run running_app/app.py --server.port {real_port}\n"
    return apps, conf, ps, d / ".streamlit.toml"


def test_stale_port_is_proposed_in_dry_run(tmp_path):
    apps, conf, ps, toml = _stale_port_setup(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)
    out = _repair(tmp_path, env, apply=False)
    action = _action(out, "stale-port", "running_app")
    assert action["from"] == 8501
    assert action["to"] == 8600
    assert action["applied"] is False
    assert toml.read_text() == "port = 8501\n"


def test_stale_port_is_updated_with_apply_and_backed_up(tmp_path):
    apps, conf, ps, toml = _stale_port_setup(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)
    out = _repair(tmp_path, env, apply=True)
    action = _action(out, "stale-port", "running_app")
    assert action["applied"] is True
    # This fixture's .streamlit.toml also has no "entrypoint = ..." line
    # (an old-format file, from before the per-app systemd unit fix), so
    # the same --apply pass also runs case 4 (missing-entrypoint-record)
    # against the very same file — both land in it.
    port_text = toml.read_text()
    assert "port = 8600" in port_text
    assert 'entrypoint = "running_app/app.py"' in port_text

    # A single backup captures the file exactly as it was before EITHER
    # case touched it — case 4 must never create a second backup once
    # case 3 already has.
    backups = list(toml.parent.glob(".streamlit.toml.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == "port = 8501\n"


def test_matching_port_is_not_flagged(tmp_path):
    """"matching port" refers specifically to the stale-port case: a
    correctly-recorded port must never be reported stale. This fixture's
    file still has no "entrypoint = ..." line, so it legitimately remains
    a missing-entrypoint-record candidate — a distinct anomaly, not a
    regression of this one."""
    apps, conf, ps, toml = _stale_port_setup(tmp_path, declared_port="8600", real_port="8600")
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)
    out = _repair(tmp_path, env, apply=False)
    actions = [a for a in out["actions"] if a["app"] == "running_app"]
    assert all(a["type"] != "stale-port" for a in actions)


def test_stale_port_without_a_running_process_is_not_repaired(tmp_path):
    """No live process = no reference truth to correct from; `app audit`
    still flags stale-port on its own, but `app repair` proposes nothing
    here rather than guessing."""
    apps, conf, ps, toml = _stale_port_setup(tmp_path)
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps="")  # nothing running
    out = _repair(tmp_path, env, apply=False)
    assert [a for a in out["actions"] if a["app"] == "running_app"] == []


# ─────────────────────────────────────────────────────────────────────
# Cross-cutting: simulation mode writes nothing, ever
# ─────────────────────────────────────────────────────────────────────

def test_dry_run_across_all_three_cases_writes_nothing_at_all(tmp_path):
    """Combine all three repairable scenarios in one run and assert the
    dry-run leaves every single file byte-for-byte identical, and creates
    no backup files anywhere."""
    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n\n'
        '[apps.tong_shu_app]\nname = "tong_shu_app"\npath = "tong_shu_app.py"\nenabled = true\n\n'
        '[apps.wuyun_liuqi]\nname = "wuyun_liuqi"\npath = "tong_shu_app.py"\nenabled = true\n'
    )
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "tong_shu_app.py").write_text("import streamlit\n")
    (apps / "wuyun_liuqi.py").write_text("import streamlit\n")
    d = apps / "running_app"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text("port = 8501\n")

    conf_before = conf.read_text()
    toml_before = (d / ".streamlit.toml").read_text()

    env = _env(tmp_path, apps_dir=apps, conf=conf,
                ps="streamlit run running_app/app.py --server.port 8600\n")
    out = _repair(tmp_path, env, apply=False)

    assert out["summary"]["total"] >= 3
    assert out["summary"]["applied"] == 0
    assert all(a["applied"] is False for a in out["actions"])

    assert conf.read_text() == conf_before
    assert (d / ".streamlit.toml").read_text() == toml_before
    assert list(tmp_path.rglob("*.bak.*")) == []


def test_repair_never_removes_app_files_or_directories(tmp_path):
    """Blanket guard: whatever repair does, no app file or directory
    disappears from disk, even in --apply mode."""
    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.test_app]\nname = "test_app"\npath = "test_app.py"\nenabled = true\n\n'
        '[apps.tong_shu_app]\nname = "tong_shu_app"\npath = "tong_shu_app.py"\nenabled = true\n\n'
        '[apps.wuyun_liuqi]\nname = "wuyun_liuqi"\npath = "tong_shu_app.py"\nenabled = true\n'
    )
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "tong_shu_app.py").write_text("import streamlit\n")
    (apps / "wuyun_liuqi.py").write_text("import streamlit\n")
    d = apps / "running_app"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    (d / ".streamlit.toml").write_text("port = 8501\n")

    disk_entries_before = sorted(p.name for p in apps.rglob("*") if p.name != ".streamlit.toml")

    env = _env(tmp_path, apps_dir=apps, conf=conf,
                ps="streamlit run running_app/app.py --server.port 8600\n")
    _repair(tmp_path, env, apply=True)

    disk_entries_after = sorted(
        p.name for p in apps.rglob("*")
        if p.name != ".streamlit.toml" and ".bak." not in p.name
    )
    assert disk_entries_before == disk_entries_after


# ─────────────────────────────────────────────────────────────────────
# Case 4: missing-entrypoint-record — the per-app systemd unit migration
# step. lxc/streamlit-launch refuses to start an app whose .streamlit.toml
# has no "entrypoint = ..." line (never re-derives it itself, #958). Most
# of the fleet was started some other way and has no port file at all;
# `app repair --apply` is how it gets one, sourced from the port the
# process is ACTUALLY listening on — never a guessed port.
# ─────────────────────────────────────────────────────────────────────

def test_running_flat_script_with_no_port_file_gets_one_created(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "billets.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf,
                ps="streamlit run billets.py --server.port=8517\n")

    out = _repair(tmp_path, env, apply=False)
    action = _action(out, "missing-entrypoint-record", "billets")
    assert action["port"] == 8517
    assert action["entrypoint"] == "billets.py"
    assert action["applied"] is False
    assert not (apps / ".streamlit-billets.toml").exists()

    out2 = _repair(tmp_path, env, apply=True)
    action2 = _action(out2, "missing-entrypoint-record", "billets")
    assert action2["applied"] is True
    port_file = apps / ".streamlit-billets.toml"
    assert port_file.exists()
    text = port_file.read_text()
    assert "port = 8517" in text
    assert 'entrypoint = "billets.py"' in text


def test_running_directory_app_with_no_port_file_gets_one_created(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    d = apps / "control"
    d.mkdir()
    (d / "test_dashboard.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf,
                ps="streamlit run control/test_dashboard.py --server.port=8600\n")

    out = _repair(tmp_path, env, apply=True)
    action = _action(out, "missing-entrypoint-record", "control")
    assert action["applied"] is True
    text = (d / ".streamlit.toml").read_text()
    assert "port = 8600" in text
    assert 'entrypoint = "control/test_dashboard.py"' in text


def test_app_not_running_and_without_a_port_file_is_left_alone(tmp_path):
    """No live process = no reference port to record from; nothing is
    invented. The app remains a plain "sleeping, never configured"
    anomaly for `app audit` to report — not something repair guesses at."""
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "dormant.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps="")

    out = _repair(tmp_path, env, apply=False)
    assert [a for a in out["actions"] if a["app"] == "dormant"] == []


def test_app_already_fully_recorded_is_not_flagged_again(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "done.py").write_text("import streamlit\n")
    (apps / ".streamlit-done.toml").write_text(
        'port = 8501\nentrypoint = "done.py"\n'
    )
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf,
                ps="streamlit run done.py --server.port=8501\n")

    out = _repair(tmp_path, env, apply=False)
    assert [a for a in out["actions"]
            if a["app"] == "done" and a["type"] == "missing-entrypoint-record"] == []

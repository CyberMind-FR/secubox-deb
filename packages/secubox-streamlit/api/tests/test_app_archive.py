# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the archived-app lifecycle (#956).

29 apps were found present on disk but never declared in streamlit.toml.
Decision: bring them in as `archived = true` — repaired and known, but
never published or started, ready to be reactivated with one command.

The pre-existing `enabled` field never actually gated anything for apps
(only `cmd_instance_list` ever read it, and only for instances) — this
suite locks down that `archived` is different: it is actually honoured by
the bulk start path (`autostart`) and by explicit `app start`.

`app archive` / `app archive --undeclared` / `app unarchive` follow the
exact `app repair` convention: dry-run by default, JSON output, timestamped
backup of streamlit.toml before any write, and never touching app files or
directories.
"""
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _env(tmp_path, apps_dir=None, conf=None, ps=None, extra_path=""):
    apps_dir = apps_dir or (tmp_path / "apps")
    apps_dir.mkdir(exist_ok=True)
    conf_path = conf or (tmp_path / "streamlit.toml")
    if not conf_path.exists():
        conf_path.write_text("")
    ps_path = tmp_path / "ps.txt"
    ps_path.write_text(ps or "")
    path = "/usr/bin:/bin:/usr/sbin:/sbin"
    if extra_path:
        path = f"{extra_path}:{path}"
    return {
        "PATH": path,
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf_path),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_path),
    }


def _run(args, env, timeout=30):
    r = subprocess.run(["bash", str(CTL)] + args, capture_output=True, text=True,
                        env=env, timeout=timeout)
    return r


def _run_json(args, env, timeout=30):
    r = _run(args, env, timeout=timeout)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ─────────────────────────────────────────────────────────────────────
# `app start` refuses an archived app explicitly
# ─────────────────────────────────────────────────────────────────────

def test_app_start_refuses_an_archived_app(tmp_path):
    apps = tmp_path / "apps"
    d = apps / "sleepy"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.sleepy]\nname = "sleepy"\npath = "sleepy/app.py"\n'
        'archived = true\nenabled = false\n'
    )
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    r = _run(["app", "start", "sleepy"], env)
    assert r.returncode != 0
    assert "archiv" in r.stderr.lower()
    assert "unarchive" in r.stderr.lower()


def test_app_start_still_works_for_a_non_archived_app_declared_false(tmp_path):
    """Regression guard: only `archived = true` blocks the start, not a
    merely-present `archived = false` line or its absence."""
    apps = tmp_path / "apps"
    d = apps / "awake"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.awake]\nname = "awake"\npath = "awake/app.py"\narchived = false\n')
    env = _env(tmp_path, apps_dir=apps, conf=conf)
    r = _run(["app", "start", "awake"], env)
    # It still fails, but for an entirely different reason (no LXC in test
    # env) — never the archived-refusal message.
    assert "archiv" not in (r.stderr or "").lower()


# ─────────────────────────────────────────────────────────────────────
# Bulk `autostart` skips archived apps, but not the others
# ─────────────────────────────────────────────────────────────────────

def test_autostart_skips_archived_apps_but_starts_the_rest(tmp_path):
    apps = tmp_path / "apps"
    for name in ("archived_one", "live_one"):
        d = apps / name
        d.mkdir(parents=True)
        (d / "app.py").write_text("import streamlit\n")

    conf = tmp_path / "streamlit.toml"
    conf.write_text(
        '[apps.archived_one]\nname = "archived_one"\npath = "archived_one/app.py"\n'
        'archived = true\nenabled = false\nautostart = true\nport = 8601\n\n'
        '[apps.live_one]\nname = "live_one"\npath = "live_one/app.py"\n'
        'enabled = true\nautostart = true\nport = 8602\n'
    )

    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    log_file = tmp_path / "lxc-attach.log"
    (fake_bin / "lxc-info").write_text("#!/bin/sh\necho RUNNING\nexit 0\n")
    (fake_bin / "lxc-info").chmod(0o755)
    (fake_bin / "lxc-attach").write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do printf \'%s\\n\' "$a" >> "$LXC_ATTACH_LOG"; done\n'
        "printf '---\\n' >> \"$LXC_ATTACH_LOG\"\n"
        "exit 0\n"
    )
    (fake_bin / "lxc-attach").chmod(0o755)

    env = _env(tmp_path, apps_dir=apps, conf=conf, extra_path=str(fake_bin))
    env["LXC_ATTACH_LOG"] = str(log_file)

    r = _run(["autostart"], env)
    assert r.returncode == 0, r.stderr

    log_text = log_file.read_text() if log_file.exists() else ""
    assert "live_one" in log_text
    assert "archived_one" not in log_text

    idle_dir = tmp_path / "idle"
    assert (idle_dir / "live_one.state").exists()
    assert not (idle_dir / "archived_one.state").exists()


# ─────────────────────────────────────────────────────────────────────
# `app archive <name>` — dry-run writes nothing
# ─────────────────────────────────────────────────────────────────────

def test_archive_dry_run_writes_nothing(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.foo]\nname = "foo"\npath = "foo.py"\nenabled = true\n')
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "foo.py").write_text("import streamlit\n")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    before = conf.read_text()
    out = _run_json(["app", "archive", "foo"], env)

    assert out["apply"] is False
    action = out["actions"][0]
    assert action["applied"] is False
    assert conf.read_text() == before
    assert list(tmp_path.glob("streamlit.toml.bak.*")) == []


def test_archive_with_apply_sets_archived_and_disables_and_backs_up(tmp_path):
    conf = tmp_path / "streamlit.toml"
    original = '[apps.foo]\nname = "foo"\npath = "foo.py"\nenabled = true\n'
    conf.write_text(original)
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "foo.py").write_text("import streamlit\n")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    out = _run_json(["app", "archive", "foo", "--apply"], env)
    action = out["actions"][0]
    assert action["applied"] is True

    text = conf.read_text()
    assert "archived = true" in text
    assert "enabled = false" in text

    backups = list(tmp_path.glob("streamlit.toml.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == original

    # The disk file was never touched.
    assert (apps / "foo.py").exists()


def test_archive_unknown_app_is_an_error(tmp_path):
    env = _env(tmp_path)
    r = _run(["app", "archive", "ghost", "--apply"], env)
    assert r.returncode != 0
    assert "non déclarée" in r.stderr or "not declared" in r.stderr.lower()


# ─────────────────────────────────────────────────────────────────────
# `app archive <name>` refuses a running app without --force
# ─────────────────────────────────────────────────────────────────────

def test_archive_refuses_a_running_app_without_force(tmp_path):
    apps = tmp_path / "apps"
    d = apps / "busy"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.busy]\nname = "busy"\npath = "busy/app.py"\nenabled = true\n')
    ps = "streamlit run busy/app.py --server.port 8600\n"
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)

    out = _run_json(["app", "archive", "busy", "--apply"], env)
    action = out["actions"][0]
    assert action["running"] is True
    assert action["blocked"] is True
    assert action["applied"] is False
    assert "force" in action["reason"].lower()
    # Config untouched, no backup created.
    assert "archived" not in conf.read_text()
    assert list(tmp_path.glob("streamlit.toml.bak.*")) == []


def test_archive_running_app_succeeds_with_force(tmp_path):
    apps = tmp_path / "apps"
    d = apps / "busy"
    d.mkdir(parents=True)
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.busy]\nname = "busy"\npath = "busy/app.py"\nenabled = true\n')
    ps = "streamlit run busy/app.py --server.port 8600\n"
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)

    out = _run_json(["app", "archive", "busy", "--apply", "--force"], env)
    action = out["actions"][0]
    assert action["blocked"] is False
    assert action["applied"] is True
    assert "archived = true" in conf.read_text()

    # `app archive --force` only edits the declaration; it never stops the
    # running process itself (nothing in this test doubles `kill`/`pkill`,
    # so if the command tried to stop the app it would either fail loudly
    # or need those tools — its absence from PATH would surface as an
    # error, and the command above already asserted returncode 0 via
    # _run_json).


# ─────────────────────────────────────────────────────────────────────
# `app archive --undeclared` — bulk-declares the 29 undeclared apps,
# directly in archived state
# ─────────────────────────────────────────────────────────────────────

def test_archive_undeclared_dry_run_declares_nothing(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "orphan_script.py").write_text("import streamlit\n")
    d = apps / "orphan_dir"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    out = _run_json(["app", "archive", "--undeclared"], env)
    assert out["apply"] is False
    assert out["summary"]["total"] == 2
    assert out["summary"]["applied"] == 0
    assert conf.read_text() == ""
    assert list(tmp_path.glob("streamlit.toml.bak.*")) == []


def test_archive_undeclared_apply_declares_all_disk_only_apps_as_archived(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "orphan_script.py").write_text("import streamlit\n")
    d = apps / "orphan_dir"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    # Already declared: must be left alone by --undeclared.
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.already_here]\nname = "already_here"\npath = "already_here.py"\nenabled = true\n')
    (apps / "already_here.py").write_text("import streamlit\n")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    out = _run_json(["app", "archive", "--undeclared", "--apply"], env)
    assert out["summary"]["total"] == 2
    assert out["summary"]["applied"] == 2

    names = {a["app"] for a in out["actions"]}
    assert names == {"orphan_script", "orphan_dir"}
    for a in out["actions"]:
        assert a["applied"] is True

    text = conf.read_text()
    assert "[apps.orphan_script]" in text
    assert "[apps.orphan_dir]" in text
    # Already-declared app is untouched by the bulk verb.
    assert text.count("[apps.already_here]") == 1
    already_section = text.split("[apps.already_here]", 1)[1].split("[apps.", 1)[0]
    assert "archived" not in already_section

    orphan_script_section = text.split("[apps.orphan_script]", 1)[1].split("[apps.", 1)[0]
    assert 'path = "orphan_script.py"' in orphan_script_section
    assert "archived = true" in orphan_script_section
    assert "enabled = false" in orphan_script_section

    orphan_dir_section = text.split("[apps.orphan_dir]", 1)[1].split("[apps.", 1)[0]
    assert 'path = "orphan_dir/app.py"' in orphan_dir_section
    assert "archived = true" in orphan_dir_section

    backups = list(tmp_path.glob("streamlit.toml.bak.*"))
    assert len(backups) == 1

    # No disk file was created, moved, or removed.
    assert (apps / "orphan_script.py").exists()
    assert (d / "app.py").exists()


def test_archive_undeclared_then_audit_no_longer_flags_not_declared(tmp_path):
    """The whole point (#956): once archived via --undeclared, `app audit`
    must stop counting the app as not-declared, and must expose a distinct
    "archived" state rather than lumping it in with plain "sleeping"."""
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "orphan_script.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    _run_json(["app", "archive", "--undeclared", "--apply"], env)

    out = _run_json(["app", "audit"], env)
    app = [a for a in out["apps"] if a["name"] == "orphan_script"][0]
    assert "not-declared" not in app["issues"]
    assert app["declared"] is True
    assert app["archived"] is True
    assert app["state"] == "archived"
    assert app["running"] is False
    assert out["summary"]["archived"] == 1


def test_archive_undeclared_never_removes_or_renames_disk_entries(tmp_path):
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "orphan_script.py").write_text("import streamlit\n")
    d = apps / "orphan_dir"
    d.mkdir()
    (d / "app.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    before = sorted(p.relative_to(apps) for p in apps.rglob("*"))
    _run_json(["app", "archive", "--undeclared", "--apply"], env)
    after = sorted(p.relative_to(apps) for p in apps.rglob("*"))
    assert before == after


def test_archive_undeclared_respects_running_guard_per_app(tmp_path):
    """A disk-but-undeclared app that happens to already be running
    (running-unlisted, per `app audit`) follows the same running guard as
    single `app archive`: not declared/archived without --force."""
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "busy_orphan.py").write_text("import streamlit\n")
    (apps / "quiet_orphan.py").write_text("import streamlit\n")
    conf = tmp_path / "streamlit.toml"
    conf.write_text("")
    ps = "streamlit run busy_orphan.py --server.port 8610\n"
    env = _env(tmp_path, apps_dir=apps, conf=conf, ps=ps)

    out = _run_json(["app", "archive", "--undeclared", "--apply"], env)
    busy = [a for a in out["actions"] if a["app"] == "busy_orphan"][0]
    quiet = [a for a in out["actions"] if a["app"] == "quiet_orphan"][0]
    assert busy["blocked"] is True
    assert busy["applied"] is False
    assert quiet["applied"] is True

    text = conf.read_text()
    assert "[apps.busy_orphan]" not in text
    assert "[apps.quiet_orphan]" in text


# ─────────────────────────────────────────────────────────────────────
# `app unarchive` — the reverse, never starts anything
# ─────────────────────────────────────────────────────────────────────

def test_unarchive_dry_run_writes_nothing(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.foo]\nname = "foo"\npath = "foo.py"\narchived = true\nenabled = false\n')
    env = _env(tmp_path, conf=conf)
    before = conf.read_text()
    out = _run_json(["app", "unarchive", "foo"], env)
    assert out["actions"][0]["applied"] is False
    assert conf.read_text() == before


def test_unarchive_with_apply_restores_startable_state(tmp_path):
    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.foo]\nname = "foo"\npath = "foo.py"\narchived = true\nenabled = false\n')
    apps = tmp_path / "apps"
    apps.mkdir()
    (apps / "foo.py").write_text("import streamlit\n")
    env = _env(tmp_path, apps_dir=apps, conf=conf)

    out = _run_json(["app", "unarchive", "foo", "--apply"], env)
    assert out["actions"][0]["applied"] is True
    text = conf.read_text()
    assert "archived = false" in text
    assert "enabled = true" in text

    # Unarchiving never starts the app — it must still refuse to run in the
    # test env (no LXC), but crucially not with the archived-refusal
    # message, proving it's genuinely startable again.
    r = _run(["app", "start", "foo"], env)
    assert "archiv" not in (r.stderr or "").lower()

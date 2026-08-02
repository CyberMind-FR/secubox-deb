"""Regression test for the TOML-rewrite helpers in `streamlitctl` (#956
final review): `_set_toml_key_in_section`, `_remove_toml_section`,
`_set_toml_path_in_section` and `_set_app_port` all rewrite a file via
`mktemp` + `mv`.

Bug observed in production: `mktemp` (no argument) creates its temp file
in `/tmp` with mode 0600, owned by whoever runs the script. `mv` across
filesystems (here `/tmp` -> `/etc`) falls back to copy+unlink and the
*copy* keeps the mode/owner of the *source* (the 0600 tmp file), not of
the file being replaced. `/etc/secubox/streamlit.toml` went from
`0644 secubox:secubox` to `0600 root:root`; the aggregator (running as
`secubox`) could no longer read it, and `_load_streamlit_config()` swallowed
the resulting exception and returned `{}` -- autostart silently did
nothing for fifteen hours.

This test drives `streamlitctl app archive --apply`, which calls
`_set_toml_key_in_section` twice on `$SECUBOX_STREAMLIT_CONF`, and checks
that the file's mode and group survive the rewrite.
"""
import json
import os
import stat
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _env(tmp_path, apps_dir=None, conf=None):
    apps_dir = apps_dir or (tmp_path / "apps")
    apps_dir.mkdir(exist_ok=True)
    conf_path = conf or (tmp_path / "streamlit.toml")
    ps_path = tmp_path / "ps.txt"
    ps_path.write_text("")
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps_dir),
        "SECUBOX_STREAMLIT_CONF": str(conf_path),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
        "SECUBOX_STREAMLIT_PS_SOURCE": str(ps_path),
    }


def _own_supplementary_group():
    """A gid, other than our own primary gid, that we are actually a
    member of -- so chgrp to it needs no privilege. Skips the test if the
    process has no supplementary group (e.g. minimal CI container)."""
    groups = [g for g in os.getgroups() if g != os.getgid()]
    if not groups:
        return None
    return groups[0]


def test_app_archive_apply_preserves_conf_mode_and_group(tmp_path):
    other_gid = _own_supplementary_group()
    if other_gid is None:
        import pytest
        pytest.skip("process has no supplementary group to test group preservation with")

    conf = tmp_path / "streamlit.toml"
    conf.write_text('[apps.demo]\nname = "demo"\npath = "demo.py"\nenabled = true\n')
    os.chmod(conf, 0o644)
    os.chown(conf, -1, other_gid)

    before = os.stat(conf)
    assert stat.S_IMODE(before.st_mode) == 0o644
    assert before.st_gid == other_gid

    env = _env(tmp_path, conf=conf)
    r = subprocess.run(
        ["bash", str(CTL), "app", "archive", "demo", "--apply"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["actions"][0]["applied"] is True

    after = os.stat(conf)
    assert stat.S_IMODE(after.st_mode) == 0o644, (
        f"mode changed from 0644 to {oct(stat.S_IMODE(after.st_mode))} "
        "across the rewrite -- the temp file must be created in the "
        "target directory and the original mode restored before the "
        "rename, exactly the regression that broke autostart in prod"
    )
    assert after.st_gid == other_gid, (
        f"group changed from {other_gid} to {after.st_gid} across the "
        "rewrite -- owner must be preserved too"
    )

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests for the exact-match stop pattern in `streamlitctl app stop` (#961,
défaut 3).

cmd_app_stop used to build its pkill fallback as a bare substring of the
app name: `pkill -f "streamlit.*$name"`. Verified on the board: 9 real
collisions, because pkill -f matches the substring ANYWHERE in the
process command line —

    stopping 'control'         also killed 'secubox_control'
    stopping 'bazi_calculator' also killed 'bazi_calculator_1'
    stopping 'gk2_lumiere'     also killed 'fanzine_gk2_lumiere_1'
    stopping 'yijing'          also killed 'yijing-360', 'yijing.bak...'

The fix anchors the pattern on the RESOLVED ENTRYPOINT (same source of
truth as `app start`/`app audit`, via _app_entrypoint) immediately after
"streamlit run ", ERE-escaped so the entrypoint's own "." can't behave as
a wildcard.

Rather than trust a string comparison, each test captures the pattern
cmd_app_stop actually constructs — via a double of `lxc-attach` on PATH,
the same technique test_app_audit.py already uses for its -P regression
test — and evaluates it as a REAL regex (re.search) against candidate
process command lines. That's the only way to be sure the fix behaves
correctly as a pkill -f pattern, not just as a string.
"""
import re
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[2] / "sbin" / "streamlitctl"


def _stop_pattern(tmp_path, app_files, target):
    """Runs `streamlitctl app stop <target>` against a faked container
    (lxc-info reports RUNNING; lxc-attach only records its argv, nothing
    is actually executed) and returns the SBX_STOP_PATTERN value it was
    invoked with ("" if no exact pattern could be built)."""
    apps = tmp_path / "apps"
    apps.mkdir(exist_ok=True)
    for rel, content in app_files:
        p = apps / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    conf = tmp_path / "streamlit.toml"
    conf.write_text("")

    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir(exist_ok=True)
    call_log = tmp_path / "lxc-attach.args"

    fake_lxc_info = fake_bin / "lxc-info"
    fake_lxc_info.write_text("#!/bin/sh\necho RUNNING\nexit 0\n")
    fake_lxc_info.chmod(0o755)

    fake_lxc_attach = fake_bin / "lxc-attach"
    fake_lxc_attach.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do printf \'%s\\n\' "$a" >> "$LXC_ATTACH_LOG"; done\n'
        "exit 0\n"
    )
    fake_lxc_attach.chmod(0o755)

    env = {
        "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
        "LXC_ATTACH_LOG": str(call_log),
        "SECUBOX_STREAMLIT_APPS_PATH": str(apps),
        "SECUBOX_STREAMLIT_CONF": str(conf),
        "SECUBOX_STREAMLIT_IDLE_DIR": str(tmp_path / "idle"),
    }
    r = subprocess.run(["bash", str(CTL), "app", "stop", target],
                        capture_output=True, text=True, env=env, timeout=30)
    assert r.returncode == 0, r.stderr

    assert call_log.exists(), "lxc-attach was never invoked"
    for line in call_log.read_text().splitlines():
        if line.startswith("SBX_STOP_PATTERN="):
            return line[len("SBX_STOP_PATTERN="):]
    raise AssertionError("SBX_STOP_PATTERN was never passed to the container")


# ─────────────────────────────────────────────────────────────────────────
# Le cas le plus important : control / secubox_control
# ─────────────────────────────────────────────────────────────────────────

def test_stopping_control_does_not_match_secubox_control(tmp_path):
    """Board reality: `app stop control` used to also kill
    secubox_control, a completely different app that merely contains
    'control' as a substring of its name."""
    pattern = _stop_pattern(
        tmp_path,
        [("control/app.py", "import streamlit\n"),
         ("secubox_control/app.py", "import streamlit\n")],
        "control",
    )
    assert pattern, "no exact pattern was built for a resolvable app"
    assert re.search(pattern, "streamlit run control/app.py --server.port=8501"), \
        f"pattern {pattern!r} must match control's own process line"
    assert not re.search(pattern, "streamlit run secubox_control/app.py --server.port=8502"), \
        f"pattern {pattern!r} must NOT match secubox_control's process line"


# ─────────────────────────────────────────────────────────────────────────
# Les 3 autres collisions relevées sur la board
# ─────────────────────────────────────────────────────────────────────────

def test_stopping_bazi_calculator_does_not_match_bazi_calculator_1(tmp_path):
    pattern = _stop_pattern(
        tmp_path,
        [("bazi_calculator.py", "import streamlit\n"),
         ("bazi_calculator_1.py", "import streamlit\n")],
        "bazi_calculator",
    )
    assert re.search(pattern, "streamlit run bazi_calculator.py --server.port=8511")
    assert not re.search(pattern, "streamlit run bazi_calculator_1.py --server.port=8512")


def test_stopping_gk2_lumiere_does_not_match_fanzine_gk2_lumiere_1(tmp_path):
    pattern = _stop_pattern(
        tmp_path,
        [("gk2_lumiere.py", "import streamlit\n"),
         ("fanzine_gk2_lumiere_1.py", "import streamlit\n")],
        "gk2_lumiere",
    )
    assert re.search(pattern, "streamlit run gk2_lumiere.py --server.port=8521")
    assert not re.search(pattern, "streamlit run fanzine_gk2_lumiere_1.py --server.port=8522")


def test_stopping_yijing_does_not_match_its_three_lookalikes(tmp_path):
    pattern = _stop_pattern(
        tmp_path,
        [("yijing.py", "import streamlit\n"),
         ("yijing-360.py", "import streamlit\n"),
         ("yijing.bak.rolledback.20260101.py", "import streamlit\n"),
         ("yijing_oracle.py", "import streamlit\n")],
        "yijing",
    )
    assert re.search(pattern, "streamlit run yijing.py --server.port=8531")
    for lookalike in ("yijing-360.py", "yijing.bak.rolledback.20260101.py", "yijing_oracle.py"):
        assert not re.search(pattern, f"streamlit run {lookalike} --server.port=8532"), \
            f"pattern {pattern!r} must NOT match {lookalike}"


# ─────────────────────────────────────────────────────────────────────────
# Sans entrypoint résoluble : pas de repli par motif du tout
# ─────────────────────────────────────────────────────────────────────────

def test_unresolvable_app_gets_no_pattern_fallback(tmp_path):
    """An app absent from disk (never existed, or already removed)
    resolves no entrypoint — cmd_app_stop must not fall back to any
    approximate pattern in that case, only the PID file is tried."""
    pattern = _stop_pattern(tmp_path, [], "ghost")
    assert pattern == ""

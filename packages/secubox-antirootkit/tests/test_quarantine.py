# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import os
import shlex
import shutil
import subprocess

from api import quarantine


def test_prepare_returns_plan_no_side_effects(tmp_path, monkeypatch):
    # assert prepare NEVER executes: monkeypatch every side-effecting primitive
    # it could plausibly regress into using, and blow up if any is called.
    monkeypatch.setattr(
        os, "system", lambda *a, **k: (_ for _ in ()).throw(AssertionError("os.system called!"))
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess.run called!")),
    )
    monkeypatch.setattr(
        os, "chmod", lambda *a, **k: (_ for _ in ()).throw(AssertionError("os.chmod called!"))
    )
    monkeypatch.setattr(
        shutil,
        "copy",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("shutil.copy called!")),
    )
    plan = quarantine.prepare(
        "/usr/local/bin/notwork-monitoring",
        c2_ip="5.182.207.11",
        unit="notwork-monitoring.service",
        sha_fn=lambda p: "deadbeef",
    )
    assert "5.182.207.11" in plan["nft_block"]
    assert plan["sha256"] == "deadbeef"
    assert "notwork-monitoring.service" in plan["disable_unit"]
    assert plan["chmod"].startswith("chmod 000")
    assert all(isinstance(v, str) for k, v in plan.items() if v is not None)


def test_prepare_optional_fields_none():
    plan = quarantine.prepare("/tmp/x")
    assert plan["nft_block"] is None and plan["disable_unit"] is None and plan["sha256"] is None


def test_prepare_copy_and_chmod_quote_path():
    plan = quarantine.prepare("/tmp/evil bin")
    assert "chmod 000 '/tmp/evil bin'" == plan["chmod"]  # shell-quoted, not raw-interpolated
    assert "cp -a" in plan["copy"]
    assert "/root/quarantine/" in plan["copy"]


def test_prepare_quotes_shell_metacharacters():
    plan = quarantine.prepare("/tmp/x; rm -rf /")
    assert plan["chmod"] == "chmod 000 '/tmp/x; rm -rf /'"
    assert plan["copy"] == "cp -a '/tmp/x; rm -rf /' /root/quarantine/"


def test_prepare_quotes_c2_ip_and_unit_metacharacters():
    plan = quarantine.prepare(
        "/tmp/x",
        c2_ip="1.2.3.4; curl x",
        unit="evil.service; rm -rf /",
    )
    quoted_ip = shlex.quote("1.2.3.4; curl x")
    quoted_unit = shlex.quote("evil.service; rm -rf /")
    assert quoted_ip in plan["nft_block"]
    assert quoted_unit in plan["disable_unit"]
    # the bare, un-escaped separator must not appear outside the quoted form
    assert "; curl x" not in plan["nft_block"].replace(quoted_ip, "")
    assert "; rm -rf /" not in plan["disable_unit"].replace(quoted_unit, "")

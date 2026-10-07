# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import integrity


def test_debsums_parses_altered():
    def r(cmd, **k):
        class R:
            returncode = 1
            stdout = "/usr/bin/foo\n/lib/bar\n"
            stderr = ""
        return R()
    assert integrity.run_debsums(runner=r) == ["/usr/bin/foo", "/lib/bar"]


def test_debsums_tool_absent_degrades():
    def r(cmd, **k):
        raise FileNotFoundError("debsums")
    assert integrity.run_debsums(runner=r) == []


def test_debsums_no_output_degrades():
    def r(cmd, **k):
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()
    assert integrity.run_debsums(runner=r) == []


def test_authkeys_drift():
    assert integrity.authkeys_drift({"kA", "kB", "kC"}, {"kA", "kB"}) == {"kC"}


def test_authkeys_drift_no_new_keys():
    assert integrity.authkeys_drift({"kA", "kB"}, {"kA", "kB", "kC"}) == set()


def test_rkhunter_parses_warnings():
    def r(cmd, **k):
        class R:
            returncode = 1
            stdout = "Checking...\nWarning: Suspicious file /tmp/x\nOK\n"
            stderr = ""
        return R()
    assert integrity.run_rkhunter(runner=r) == ["Warning: Suspicious file /tmp/x"]


def test_rkhunter_tool_absent_degrades():
    def r(cmd, **k):
        raise FileNotFoundError("rkhunter")
    assert integrity.run_rkhunter(runner=r) == []


def test_rkhunter_no_warnings_degrades():
    def r(cmd, **k):
        class R:
            returncode = 0
            stdout = "Checking...\nOK\n"
            stderr = ""
        return R()
    assert integrity.run_rkhunter(runner=r) == []

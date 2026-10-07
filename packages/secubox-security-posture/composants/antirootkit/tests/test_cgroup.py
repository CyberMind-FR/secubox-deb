# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import cgroup


def test_jail_pid_invokes_ctl():
    calls = []
    def run(cmd, **kw):
        calls.append(cmd)
        class R: returncode = 0
        return R()
    assert cgroup.jail_pid(1234, runner=run) is True
    assert calls[0] == ["sudo", "-n", "/usr/sbin/secubox-antirootkitctl", "jail", "1234"]


def test_in_jail_reads_proc(tmp_path):
    d = tmp_path / "1234"; d.mkdir()
    (d / "cgroup").write_text("0::/sbx-untrusted.slice/x\n")
    assert cgroup.in_jail(1234, proc_root=str(tmp_path)) is True
    (d / "cgroup").write_text("0::/system.slice/y\n")
    assert cgroup.in_jail(1234, proc_root=str(tmp_path)) is False

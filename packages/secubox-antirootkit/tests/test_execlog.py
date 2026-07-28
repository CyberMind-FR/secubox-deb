# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit execlog tests
"""

from api.execlog import ExecLog
from api.execwatch import ExecEvent


def test_record_and_recent(tmp_path):
    lg = ExecLog(str(tmp_path / "e.db"))
    lg.record(
        ExecEvent(pid=1, ppid=0, uid=0, exe="/tmp/x", argv=["x"], success=True),
        "jail",
        None,
    )
    rows = lg.recent()
    assert rows[0]["exe"] == "/tmp/x"
    assert rows[0]["verdict"] == "jail"
    assert rows[0]["pkg"] is None


def test_failed_exec_count(tmp_path):
    lg = ExecLog(str(tmp_path / "e.db"))
    for _ in range(3):
        lg.record(
            ExecEvent(pid=1, ppid=0, uid=0, exe="/tmp/m", argv=[], success=False),
            "jail",
            None,
        )
    assert lg.failed_exec_count("/tmp/m", window_s=3600) >= 3


def test_append_only_no_update(tmp_path):
    import sqlite3

    lg = ExecLog(str(tmp_path / "e.db"))
    # schema must not be relied on for UPDATE; verify recorded rows are immutable by design (insert-only API)
    assert not hasattr(lg, "update")


def test_check_same_thread_false_usable_cross_thread(tmp_path):
    # FastAPI sync routes run in a threadpool worker; the API module's ExecLog
    # singleton must be constructible with check_same_thread=False and remain
    # usable from a different thread than the one that created it.
    import threading

    lg = ExecLog(str(tmp_path / "e2.db"), check_same_thread=False)
    errors = []

    def _write():
        try:
            lg.record(
                ExecEvent(pid=2, ppid=0, uid=0, exe="/tmp/y", argv=[], success=True),
                "allow",
                "somepkg",
            )
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    t = threading.Thread(target=_write)
    t.start()
    t.join()
    assert not errors
    assert lg.recent()[0]["exe"] == "/tmp/y"

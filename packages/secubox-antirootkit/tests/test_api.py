# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-antirootkit :: api/main.py tests
"""

import os
import subprocess

import pytest
from fastapi.testclient import TestClient

from api.execlog import ExecLog
from api.execwatch import ExecEvent
from api.main import create_app


@pytest.fixture
def env(tmp_path):
    # check_same_thread=False: FastAPI's sync `def` routes run in a
    # threadpool worker thread, different from the one that opens this
    # connection (see api/execlog.py + Task 10 brief).
    log = ExecLog(str(tmp_path / "execlog.db"), check_same_thread=False)
    app = create_app(execlog=log)
    return TestClient(app), log


def test_status_returns_int_execlog_rows(env):
    client, _log = env
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["execlog_rows"], int)
    assert body["execlog_rows"] == 0


def test_execlog_shows_recorded_event(env):
    client, log = env
    log.record(
        ExecEvent(pid=42, ppid=1, uid=0, exe="/tmp/suspect", argv=["suspect"], success=True),
        "jail",
        None,
    )
    r = client.get("/execlog")
    assert r.status_code == 200
    rows = r.json()
    assert any(row["exe"] == "/tmp/suspect" and row["verdict"] == "jail" for row in rows)

    # status reflects the recorded row too
    status = client.get("/status").json()
    assert status["execlog_rows"] == 1


def test_execlog_respects_limit_param(env):
    client, log = env
    for i in range(5):
        log.record(
            ExecEvent(pid=i, ppid=1, uid=0, exe=f"/tmp/x{i}", argv=[], success=True),
            "allow",
            "somepkg",
        )
    r = client.get("/execlog?limit=2")
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_status_execlog_rows_is_true_count_not_capped_by_recent_limit(env):
    # /status must report the real table size (ExecLog.count()), not
    # len(recent(limit=100)) — otherwise the dashboard badge would freeze
    # once the log grows past 100 rows on a live host.
    client, log = env
    for i in range(5):
        log.record(
            ExecEvent(pid=i, ppid=1, uid=0, exe=f"/tmp/y{i}", argv=[], success=True),
            "allow",
            "somepkg",
        )
    # /execlog queried with a small limit must not influence /status
    assert len(client.get("/execlog?limit=2").json()) == 2
    assert client.get("/status").json()["execlog_rows"] == 5


def test_alerts_returns_200_list(env):
    client, _log = env
    r = client.get("/alerts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_quarantine_prep_returns_plan(env):
    client, _log = env
    r = client.post(
        "/quarantine-prep",
        json={"path": "/usr/local/bin/notwork-monitoring", "c2_ip": "5.182.207.11"},
    )
    assert r.status_code == 200
    plan = r.json()
    assert "5.182.207.11" in plan["nft_block"]
    assert plan["chmod"].startswith("chmod 000")
    assert plan["copy"].startswith("cp -a")


def test_quarantine_prep_never_executes(env, monkeypatch):
    client, _log = env
    # Guard every side-effecting primitive the route could plausibly
    # regress into calling — the request must still succeed via the
    # side-effect-free api.quarantine.prepare() plan builder.
    monkeypatch.setattr(
        os, "system", lambda *a, **k: (_ for _ in ()).throw(AssertionError("os.system called!"))
    )
    monkeypatch.setattr(
        os, "chmod", lambda *a, **k: (_ for _ in ()).throw(AssertionError("os.chmod called!"))
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess.run called!")),
    )
    r = client.post(
        "/quarantine-prep",
        json={"path": "/usr/local/bin/notwork-monitoring", "c2_ip": "5.182.207.11", "unit": None},
    )
    assert r.status_code == 200


def test_quarantine_prep_optional_fields_default_none(env):
    client, _log = env
    r = client.post("/quarantine-prep", json={"path": "/tmp/x"})
    assert r.status_code == 200
    plan = r.json()
    assert plan["nft_block"] is None
    assert plan["disable_unit"] is None

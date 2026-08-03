"""Tests for the non-blocking wake path (ref #958 follow-up).

`POST /apps/{name}/wake` used to run `streamlitctl app wake <name> 30`
via a synchronous `subprocess.run(..., timeout=35)` directly inside an
`async def` handler — holding the shared aggregator event loop hostage for
up to 35s per request, on a route ~110 other modules' requests also flow
through. Fixed alongside the wait-budget fix (`cmd_app_wake` itself, see
test_app_wake_budget.py): the actual wake now runs in Starlette's
threadpool via `BackgroundTasks.add_task`, the same discipline already
used by `container_install` in this same file — never inline in the
request coroutine.

Three things are pinned here that test_idle.py doesn't cover:
  1. the handler hands the slow work to `BackgroundTasks.add_task` rather
     than ever calling it inline (proved by intercepting `add_task` itself,
     not just observing the eventual side effect — TestClient runs
     background tasks synchronously before returning, so only inspecting
     outcomes can't distinguish "deferred" from "inline");
  2. a wake already in flight for a name is never triggered a second time
     (the per-app lock, mirroring secubox-waker's own per-module lock);
  3. the lock is released once the background wake finishes, successfully
     or not, so a later wake for the same (now-idle-again) app isn't
     wedged forever.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api.main import app
from secubox_core.auth import require_jwt


@pytest.fixture
def client(tmp_path, monkeypatch):
    fake_ctl = tmp_path / "streamlitctl"
    fake_ctl.write_text("#!/bin/sh\nexit 0\n")
    fake_ctl.chmod(0o755)
    monkeypatch.setattr(api_main, "CTL", str(fake_ctl))

    spawned = []
    monkeypatch.setattr(api_main, "_spawn_shotter",
                         lambda name, force: spawned.append((name, force)))

    api_main._WAKE_IN_PROGRESS.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        yield TestClient(app), spawned
    finally:
        app.dependency_overrides.clear()
        api_main._WAKE_IN_PROGRESS.clear()


def test_wake_schedules_background_task_instead_of_calling_it_inline(client):
    """Intercepts BackgroundTasks.add_task itself (not just the eventual
    outcome): proves the handler DEFERS the real wake rather than running
    it as part of the request/response cycle. This is the structural
    fix — without it, the handler would still be the thing waiting on
    `streamlitctl app wake`, budget or no budget."""
    test_client, _spawned = client
    scheduled = []

    def fake_add_task(self, func, *a, **kw):
        scheduled.append((func, a, kw))

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": False}]), \
         patch("starlette.background.BackgroundTasks.add_task", fake_add_task):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert r.json()["status"] == "waking"
    assert len(scheduled) == 1
    func, a, kw = scheduled[0]
    assert func is api_main._do_wake_in_background
    assert a == ("foo",)


def test_wake_never_calls_subprocess_run_with_wake_args_synchronously(client):
    """Belt and suspenders on the same invariant as the test above, from a
    different angle: patch `subprocess.run` itself and assert it is never
    invoked with "wake" in argv while `_do_wake_in_background` is stubbed
    out — only the fast "list" pre-check may run inline."""
    test_client, _spawned = client
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        # _get_apps() resolves through _run_ctl(), which calls
        # subprocess.run(..., text=True) — stdout is str there, unlike the
        # bytes stdout _do_wake_in_background reads from its own
        # subprocess.run call (no text=True). Only the "list" pre-check
        # reaches this stub in this test (_do_wake_in_background is
        # stubbed out above), so it must match _run_ctl's str contract.
        return MagicMock(returncode=0, stdout='{"apps":[{"name":"foo","running":false}]}', stderr="")

    with patch.object(api_main, "_do_wake_in_background", lambda name: None), \
         patch("api.main.subprocess.run", side_effect=fake_run):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert r.json()["status"] == "waking"
    assert all("wake" not in c for c in calls), \
        f"the slow wake command must never run inline in the request handler: {calls}"


def test_second_wake_while_one_in_flight_never_triggers_a_second_background_task(client):
    """Mirrors secubox-waker's own per-module lock (packages/secubox-profiles/
    api/waker.py::_locks) at the per-app level: a wake already in progress
    for `name` must refuse a second concurrent trigger, not queue or race
    one."""
    test_client, _spawned = client
    scheduled = []

    def fake_add_task(self, func, *a, **kw):
        scheduled.append((func, a, kw))

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": False}]), \
         patch("starlette.background.BackgroundTasks.add_task", fake_add_task):
        r1 = test_client.post("/apps/foo/wake")
        r2 = test_client.post("/apps/foo/wake")

    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["status"] == "waking"
    assert r2.json()["status"] == "waking"
    assert len(scheduled) == 1, "a second concurrent wake for the same app must not schedule a second background task"


def test_lock_is_released_after_a_successful_background_wake(client):
    """Once `_do_wake_in_background` finishes (here: for real, via a
    mocked subprocess.run reporting success), the per-app claim must be
    released — otherwise a later wake for the same app (now idle again)
    would be refused forever."""
    test_client, spawned = client

    def fake_run(cmd, **kw):
        if "wake" in cmd:
            return MagicMock(returncode=0, stdout=b"", stderr=b"wake: foo started\n")
        return MagicMock(returncode=0, stdout=b'{"apps":[{"name":"foo","running":false}]}', stderr=b"")

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": False}]), \
         patch("api.main.subprocess.run", side_effect=fake_run):
        test_client.post("/apps/foo/wake")

    # TestClient runs BackgroundTasks to completion before returning, so by
    # now `_do_wake_in_background` has already run its `finally` clause.
    assert "foo" not in api_main._WAKE_IN_PROGRESS
    assert spawned == [("foo", False)], "a successful background wake must still fire the lazy capture hook"


def test_lock_is_released_after_a_failed_background_wake(client):
    """Same release guarantee on the failure path — a wake that never
    manages to bring the app up must not permanently block retries."""
    test_client, spawned = client

    def fake_run(cmd, **kw):
        if "wake" in cmd:
            return MagicMock(returncode=1, stdout=b"", stderr=b"wake: foo did not come up\n")
        return MagicMock(returncode=0, stdout=b'{"apps":[{"name":"foo","running":false}]}', stderr=b"")

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": False}]), \
         patch("api.main.subprocess.run", side_effect=fake_run):
        test_client.post("/apps/foo/wake")

    assert "foo" not in api_main._WAKE_IN_PROGRESS
    assert spawned == [], "a failed wake must never trigger a capture"

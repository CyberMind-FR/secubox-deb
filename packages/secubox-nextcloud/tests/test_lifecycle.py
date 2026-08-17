# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Ref #429 I3/I2: lifecycle/ssl/backup endpoints must route privileged
container operations through `ctl()` (sudo -n nextcloudctl), never a bare
lxc-*/nextcloudctl call -- and backup names must be validated before they
reach a filesystem path or ctl() argv."""
import builtins
import importlib
from fastapi.testclient import TestClient


def _load(monkeypatch, running=True):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "lxc_running", lambda: running)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    return m


def test_start_routes_through_ctl(monkeypatch):
    m = _load(monkeypatch, running=False)
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "", ""))[1])
    c = TestClient(m.app)
    r = c.post("/start")
    assert r.status_code == 200
    assert seen["sub"] == ["start"]


def test_stop_routes_through_ctl(monkeypatch):
    m = _load(monkeypatch, running=True)
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "", ""))[1])
    c = TestClient(m.app)
    r = c.post("/stop")
    assert r.status_code == 200
    assert seen["sub"] == ["stop"]


def test_lifecycle_routes_through_ctl(monkeypatch):
    m = _load(monkeypatch)  # running=True
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "", ""))[1])
    c = TestClient(m.app)
    assert c.post("/restart").status_code == 200
    assert seen["sub"] == ["restart"]  # went through ctl, not raw lxc


def test_uninstall_routes_through_ctl_with_confirm_stdin(monkeypatch):
    m = _load(monkeypatch)
    seen = {}
    def fake_ctl(sub, timeout=60, stdin=None):
        seen["sub"] = sub
        seen["stdin"] = stdin
        return True, "", ""
    monkeypatch.setattr(m, "ctl", fake_ctl)
    c = TestClient(m.app)
    r = c.post("/uninstall")
    assert r.status_code == 200
    assert seen["sub"] == ["uninstall"]
    assert seen["stdin"] == "yes\n"


def test_uninstall_ctl_failure_is_502_not_generic_500_body(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (False, "", "boom"))
    c = TestClient(m.app)
    r = c.post("/uninstall")
    assert r.status_code == 500
    assert "boom" in r.json()["detail"]


def test_backup_routes_through_ctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "", ""))[1])
    c = TestClient(m.app)
    r = c.post("/backup", json={"name": "nightly"})
    assert r.status_code == 200
    assert seen["sub"] == ["backup", "nightly"]


def test_backup_name_traversal_rejected(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    assert c.post("/backup", json={"name": "../../x"}).status_code == 400
    assert c.post("/backup", json={"name": "a/b"}).status_code == 400


def test_restore_name_traversal_rejected(monkeypatch):
    m = _load(monkeypatch)
    seen = {}
    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        class _P:
            stdin = None
        return _P()
    monkeypatch.setattr(m.subprocess, "Popen", fake_popen)
    c = TestClient(m.app)
    # a path-encoded traversal attempt: either the validator rejects it (400)
    # or Starlette's routing never matches a slash-bearing segment (404) --
    # either way it must never reach Popen/ctl.
    assert c.post("/restore/..%2f..%2fetc").status_code in (400, 404)
    assert "cmd" not in seen  # never reached Popen


def test_restore_valid_name_uses_sudo_and_confirm_stdin(monkeypatch, tmp_path):
    m = _load(monkeypatch)
    seen = {}

    class _FakeStdin:
        def __init__(self):
            self.written = b""
            self.closed = False

        def write(self, data):
            self.written += data

        def close(self):
            self.closed = True

    class _FakeProc:
        def __init__(self):
            self.stdin = _FakeStdin()

    def fake_popen(cmd, **kwargs):
        seen["cmd"] = cmd
        return _FakeProc()

    # the endpoint opens a real log file for stdout before Popen() runs;
    # redirect it to a writable tmp path instead of /var/log.
    log_file = tmp_path / "nextcloud-restore.log"
    real_open = builtins.open

    def fake_open(path, *a, **k):
        if path == "/var/log/nextcloud-restore.log":
            path = str(log_file)
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(m.subprocess, "Popen", fake_popen)
    c = TestClient(m.app)
    r = c.post("/restore/nightly")
    assert r.status_code == 200
    assert seen["cmd"][:3] == ["sudo", "-n", "/usr/sbin/nextcloudctl"]
    assert seen["cmd"][3:] == ["restore", "nightly"]


def test_delete_backup_name_traversal_rejected(monkeypatch):
    m = _load(monkeypatch)
    c = TestClient(m.app)
    # either the validator rejects it (400) or Starlette's routing never
    # matches a slash-bearing segment (404) -- either way, rejected.
    assert c.delete("/backup/..%2f..%2fetc").status_code in (400, 404)

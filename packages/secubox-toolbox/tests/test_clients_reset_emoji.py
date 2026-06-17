# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import pathlib
from secubox_toolbox import store


def _tmpdb(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", pathlib.Path(tmp_path / "toolbox.db"))
    with store._conn():
        pass
    return store


def test_latest_user_agent(tmp_path, monkeypatch):
    s = _tmpdb(tmp_path, monkeypatch)
    with s._conn() as c:
        c.execute("INSERT INTO consents(mac_hash,ts,ttl_seconds,ip,user_agent) "
                  "VALUES('m1',200,3600,'1.2.3.4','Mozilla/5.0 (iPhone) UA')")
    assert s.latest_user_agent("m1") == "Mozilla/5.0 (iPhone) UA"
    assert s.latest_user_agent("nope") is None


def test_reset_all_clients_loops(monkeypatch):
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, social as so
    calls = {"reset": [], "wipe": []}
    monkeypatch.setattr(st, "list_clients", lambda: [{"mac_hash": "a"}, {"mac_hash": "b"}])
    monkeypatch.setattr(st, "reset_client", lambda mh: calls["reset"].append(mh) or 3)
    monkeypatch.setattr(so, "wipe_mac", lambda mh: calls["wipe"].append(mh) or 2)
    out = api._reset_all_clients()
    assert calls["reset"] == ["a", "b"] and calls["wipe"] == ["a", "b"]
    assert out == {"ok": True, "clients_reset": 2, "rows_deleted": 10}


def test_reset_all_clients_one_failure_continues(monkeypatch):
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, social as so
    monkeypatch.setattr(st, "list_clients", lambda: [{"mac_hash": "a"}, {"mac_hash": "b"}])
    def _rc(mh):
        if mh == "a":
            raise RuntimeError("boom")
        return 3
    monkeypatch.setattr(st, "reset_client", _rc)
    monkeypatch.setattr(so, "wipe_mac", lambda mh: 2)
    out = api._reset_all_clients()
    assert out["ok"] is True and out["clients_reset"] == 1

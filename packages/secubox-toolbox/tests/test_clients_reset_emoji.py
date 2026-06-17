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


def test_clients_rich_enriches_device_and_geo(monkeypatch):
    import asyncio
    import secubox_toolbox.api as api
    from secubox_toolbox import store as st, geo as g
    monkeypatch.setattr(st, "list_clients", lambda: [
        {"mac_hash": "m1", "ip": "1.2.3.4", "state": "validated",
         "score": 10, "level": "r2", "first_seen": 0, "last_seen": 0}])
    monkeypatch.setattr(st, "latest_user_agent",
                        lambda mh: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X)")
    monkeypatch.setattr(g, "lookup",
                        lambda ip: {"flag": "🇫🇷", "country_iso": "FR", "asn_org": "OVH"})
    out = asyncio.get_event_loop().run_until_complete(api.admin_clients_rich())
    c = out["clients"][0]
    assert c["flag"] == "🇫🇷" and c["country_iso"] == "FR" and c["asn_org"] == "OVH"
    assert "device" in c and "device_emoji" in c
    # iPhone UA should classify to a phone device (not the bare placeholder semantics)
    assert c["device"]  # non-empty device label derived from UA

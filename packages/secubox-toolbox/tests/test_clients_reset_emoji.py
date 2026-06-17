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

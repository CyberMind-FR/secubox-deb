from api.reach import reach_snippet, snippet_path, REACH_LEVELS
import pytest

def test_localhost():
    assert reach_snippet("localhost", False) == "allow 127.0.0.1;\ndeny all;\n"

def test_lan_has_rfc1918_and_localhost():
    s = reach_snippet("lan", False)
    for frag in ("allow 127.0.0.1;", "allow 10.0.0.0/8;", "allow 172.16.0.0/12;",
                 "allow 192.168.0.0/16;", "deny all;"):
        assert frag in s
    assert "10.10.0.0/24" not in s   # mesh off

def test_wan_is_empty_public():
    assert reach_snippet("wan", False) == ""

def test_mesh_adds_mesh_cidr_and_still_denies():
    s = reach_snippet("localhost", True)
    assert "allow 10.10.0.0/24;" in s and "deny all;" in s

def test_wan_plus_mesh_still_public():
    assert reach_snippet("wan", True) == ""   # public already covers mesh

def test_invalid_reach_raises():
    with pytest.raises(ValueError):
        reach_snippet("internet", False)

def test_snippet_path():
    assert str(snippet_path("zigbee.gk2.secubox.in")).endswith(
        "/etc/nginx/snippets/exposure/zigbee.gk2.secubox.in.conf")

def test_reach_levels():
    assert REACH_LEVELS == ("localhost", "lan", "wan")

def test_write_and_read_roundtrip(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("a.example", "lan", True)
    got = r.read_snippet_reach("a.example")
    assert got == {"reach": "lan", "mesh": True}

def test_read_missing_is_wan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    assert r.read_snippet_reach("nope.example") == {"reach": "wan", "mesh": False}

def test_write_wan_then_read(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("b.example", "wan", False)
    assert r.read_snippet_reach("b.example") == {"reach": "wan", "mesh": False}

def test_write_localhost(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("c.example", "localhost", False)
    assert r.read_snippet_reach("c.example") == {"reach": "localhost", "mesh": False}
    assert not (tmp_path / "c.example.conf.tmp").exists()

def test_load_record_defaults_public_to_wan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    rec = r.load_record("pub.example", is_public_now=True)
    assert rec == {"vhost": "pub.example", "reach": "wan", "mesh": False, "tor": False}

def test_load_record_defaults_private_to_lan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    rec = r.load_record("priv.example", is_public_now=False)
    assert rec == {"vhost": "priv.example", "reach": "lan", "mesh": False, "tor": False}

def test_load_record_reads_existing_snippet(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("x.example", "localhost", True)
    rec = r.load_record("x.example", is_public_now=True)
    assert rec["reach"] == "localhost" and rec["mesh"] is True

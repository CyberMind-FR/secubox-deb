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

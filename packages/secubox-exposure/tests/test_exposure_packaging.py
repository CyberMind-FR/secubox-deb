from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_default_snippet_is_lan():
    s = (ROOT / "conf" / "nginx-exposure-default.conf").read_text()
    assert "allow 192.168.0.0/16;" in s and "deny all;" in s
    assert "10.10.0.0/24" not in s   # mesh off by default

def test_rules_installs_snippet_dir_and_default():
    r = (ROOT / "debian" / "rules").read_text()
    assert "snippets/exposure" in r
    assert "nginx-exposure-default.conf" in r

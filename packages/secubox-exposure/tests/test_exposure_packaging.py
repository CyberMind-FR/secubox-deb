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


def test_rules_installs_tor_reconcile_persist_unit():
    """FINAL-REVIEW packaging fix: without shipping the sbin script + unit,
    tor_reconcile_persist() never runs on boot and persist-on-boot is inert."""
    r = (ROOT / "debian" / "rules").read_text()
    assert "secubox-exposure-tor-reconcile" in r
    assert "usr/sbin" in r
    assert "usr/lib/systemd/system" in r


def test_postinst_enables_tor_reconcile_unit():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "systemctl enable secubox-exposure-tor-reconcile.service" in p


def test_sbin_and_unit_files_present_and_valid():
    sbin = ROOT / "sbin" / "secubox-exposure-tor-reconcile"
    unit = ROOT / "systemd" / "secubox-exposure-tor-reconcile.service"
    assert sbin.exists()
    assert unit.exists()
    assert "tor_reconcile_persist" in sbin.read_text()
    assert "ExecStart=/usr/sbin/secubox-exposure-tor-reconcile" in unit.read_text()

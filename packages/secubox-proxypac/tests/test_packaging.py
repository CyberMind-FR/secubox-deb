from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_control_metadata():
    c = (ROOT / "debian" / "control").read_text()
    assert "Package: secubox-proxypac" in c
    assert "Standards-Version: 4.6.2" in c
    assert "Depends:" in c and "secubox-core" in c
    # /proxy.pac LAN gate relies on secubox-hub's real_ip rewrite behind HAProxy
    assert "secubox-hub" in c

def test_rules_installs_all_artifacts():
    r = (ROOT / "debian" / "rules").read_text()
    for frag in ["proxypac", "sbin/proxypac-gen", "nginx/proxypac.conf",
                 "systemd/secubox-proxypac-gen.path", "conf/rules.d", "www"]:
        assert frag in r

def test_postinst_enables_regen_and_seeds_rules():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "systemctl enable --now secubox-proxypac-gen.path" in p
    assert "systemctl enable --now secubox-proxypac-gen.timer" in p
    assert "proxypac-gen" in p  # initial generation

def test_no_conflicting_compat_file():
    # debhelper forbids both debian/compat AND Build-Depends: debhelper-compat
    assert not (ROOT / "debian" / "compat").exists()
    assert "debhelper-compat (= 13)" in (ROOT / "debian" / "control").read_text()

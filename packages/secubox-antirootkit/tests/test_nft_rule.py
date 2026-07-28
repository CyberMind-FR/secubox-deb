from pathlib import Path

def test_antiescape_rule():
    """Test that the nft anti-escape rule file has all required components."""
    txt = Path("nft/secubox-antiescape.nft").read_text()
    assert "sbx-untrusted.slice" in txt
    assert "cgroupv2" in txt
    assert "drop" in txt
    # LAN carve-out so a jailed proc can still reach the local mgmt net (no exfil, but debuggable)
    assert "192.168.0.0/16" in txt or "@lan_safe" in txt
    assert "hook output" in txt

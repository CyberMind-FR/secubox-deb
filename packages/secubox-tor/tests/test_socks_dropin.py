# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le SOCKS exposé au LAN ne doit JAMAIS être ouvert : SocksPort sur l'IP LAN
(pas 0.0.0.0), et une SocksPolicy dont le `reject *` vient EN DERNIER (Tor
applique la première policy qui matche)."""
from pathlib import Path

CONF = Path(__file__).resolve().parents[1] / "conf" / "torrc.d" / "50-secubox-socks-lan.conf"

def test_socksport_bound_to_lan_ip_not_wildcard():
    t = CONF.read_text()
    assert "SocksPort 192.168.1.200:9050" in t
    assert "0.0.0.0" not in t

def test_policy_accepts_lan_and_wg():
    t = CONF.read_text()
    assert "SocksPolicy accept 192.168.0.0/16" in t
    assert "SocksPolicy accept 10.99.0.0/16" in t

def test_reject_all_is_last_policy_line():
    lines = [l.strip() for l in CONF.read_text().splitlines()
             if l.strip().startswith("SocksPolicy")]
    assert lines[-1] == "SocksPolicy reject *", f"reject * doit être en dernier, got {lines}"

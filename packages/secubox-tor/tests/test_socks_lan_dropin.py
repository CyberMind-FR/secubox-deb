import subprocess, re, os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_socks_lan_template_has_no_socks_policy():
    tpl = (ROOT / "conf/torrc.d/50-secubox-socks-lan.conf").read_text()
    assert "SocksPort" in tpl
    assert "SocksPolicy" not in tpl, "SocksPolicy est GLOBALE — casserait le port mesh"
    assert "__LAN_IP__" in tpl, "l'IP doit être un placeholder substitué au postinst"
    assert "0.0.0.0" not in tpl

def test_lan_ip_helper_prints_a_private_ipv4():
    out = subprocess.run(["bash", str(ROOT / "sbin/tor-lan-ip")],
                         capture_output=True, text=True)
    ip = out.stdout.strip()
    assert re.match(r"^(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.\d+\.\d+\.\d+)$", ip), f"got {ip!r}"
    # ne doit jamais renvoyer une IP wg/docker/mesh
    assert not ip.startswith(("10.99.", "10.100.", "10.10.", "172.17.")), ip

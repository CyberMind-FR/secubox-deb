# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import subprocess
from pathlib import Path

CTL = str(Path(__file__).resolve().parents[1] / "sbin" / "picobrewctl")

def _emit() -> str:
    p = subprocess.run(["bash", CTL, "__emit-config"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout

def test_config_pins_the_allocated_ip_and_bridge():
    """Une IP erronée ici = conteneur injoignable, sans erreur visible."""
    cfg = _emit()
    assert "lxc.net.0.ipv4.address = 10.100.0.140/24" in cfg
    assert "lxc.net.0.ipv4.gateway = 10.100.0.1" in cfg
    assert "lxc.net.0.link = br-lxc" in cfg

def test_config_starts_container_automatically():
    """L'appareil doit revivre après un reboot de la box sans geste humain."""
    assert "lxc.start.auto = 1" in _emit()

def test_config_declares_rootfs_and_hostname():
    cfg = _emit()
    assert "lxc.rootfs.path = dir:/data/lxc/picobrew/rootfs" in cfg
    assert "lxc.uts.name = picobrew" in cfg

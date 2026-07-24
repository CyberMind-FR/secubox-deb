# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: proxypac.role — détection passive master/slave (read-only)."""
import subprocess


def _live_probe():
    """Lecture d'état seulement : aucun paquet DHCP émis."""
    lan_ip = ""
    try:
        lan_ip = subprocess.run(["/usr/sbin/tor-lan-ip"], capture_output=True,
                                text=True, timeout=5).stdout.strip()
    except Exception:
        pass
    ss = ""
    try:
        ss = subprocess.run(["ss", "-ulnp"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        pass
    dhcp = bool(lan_ip) and (f"{lan_ip}:67" in ss or "0.0.0.0:67" in ss)
    dns = bool(lan_ip) and (f"{lan_ip}:53" in ss)
    return {"lan_ip": lan_ip, "dhcp_on_lan": dhcp, "dns_on_lan": dns}


def detect(probe=None):
    p = probe if probe is not None else _live_probe()
    if p.get("dhcp_on_lan"):
        return {"role": "master", "dns_resolver": p.get("dns_on_lan", False),
                "lan_ip": p.get("lan_ip", ""), "tier": 1}
    if p.get("dns_on_lan"):
        return {"role": "slave", "dns_resolver": True, "lan_ip": p.get("lan_ip", ""), "tier": 2}
    return {"role": "slave", "dns_resolver": False, "lan_ip": p.get("lan_ip", ""), "tier": 3}

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100/#3117 — le vhost de boot n'écoute plus sur l'adresse de gk2 : l'adresse LAN de la box est posée à l'activation."""
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1]
VHOST = ICI / "nginx" / "boot-vhost.conf"
SERVE = ICI / "sbin" / "secubox-netboot-serve"


def test_gabarit_sans_adresse_de_gk2():
    s = VHOST.read_text()
    assert "192.168.1.200" not in s
    assert "listen @ADRESSE_LAN@:8099;" in s


def test_plus_de_location_sbxboot_livree():
    assert not (ICI / "nginx" / "netboot-server.conf").exists()
    assert "netboot-server.conf" not in (ICI / "debian" / "rules").read_text()


def _adresse(env):
    """Appelle la seule fonction adresse_lan du script (sans rien activer)."""
    r = subprocess.run(["bash", "-c", f"source {SERVE} --bibliotheque; adresse_lan"],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.strip()


def test_adresse_imposee_par_l_environnement():
    assert _adresse({"PATH": "/usr/bin:/bin", "SBX_NETBOOT_ADRESSE": "192.168.1.94"}) == (0, "192.168.1.94")


def test_adresse_publique_ou_invalide_refusee():
    for a in ("8.8.8.8", "127.0.0.1", "192.168.1.300", "1.2.3", "10.10.0.8"):
        rc, _ = _adresse({"PATH": "/usr/bin:/bin", "SBX_NETBOOT_ADRESSE": a})
        assert rc != 0, a

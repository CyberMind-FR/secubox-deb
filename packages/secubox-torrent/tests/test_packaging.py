# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-torrent :: packaging structural tests (v2.0.0 pivot)

Guards the Transmission -> WebTorrent/LXC packaging pivot (#917, Task 8):
old FastAPI/Transmission control-plane gone, LXC deps present, install-lxc.sh
wired into postinst, and the public vhost lands in sites-available (not the
location-snippet secubox.d/ dir).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(p):
    return (ROOT / p).read_text()


def test_control_is_v2_no_transmission():
    c = _read("debian/control")
    assert "python3-uvicorn" not in c          # old FastAPI gone
    assert "transmission" not in c.lower()
    assert "lxc" in c.lower()


def test_changelog_is_2_0_0():
    assert _read("debian/changelog").startswith("secubox-torrent (2.0.0-1~bookworm1)")


def test_postinst_runs_install_lxc():
    assert "install-lxc.sh" in _read("debian/postinst")


def test_no_old_fastapi_main():
    assert not (ROOT / "api" / "main.py").exists()


def test_no_old_host_systemd_unit():
    assert not (ROOT / "systemd" / "secubox-torrent.service").exists()


def test_vhost_installed_to_sites_available_not_secubox_d():
    rules = _read("debian/rules")
    assert "sites-available" in rules
    # Guard against reintroducing the location-snippet dir for this full vhost.
    assert "secubox-torrent/etc/nginx/secubox.d/torrent.conf" not in rules
    assert "secubox-torrent/etc/nginx/secubox-vhost.d" not in rules

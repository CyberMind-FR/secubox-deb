# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_dropin_is_mesh_only_and_default_drop_friendly():
    nft = (ROOT / "nft" / "zz-secubox-assist.conf").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert "0.0.0.0" not in nft


def test_sudoers_is_scoped_to_assistctl():
    s = (ROOT / "sudoers" / "secubox-assist").read_text()
    assert "/usr/sbin/secubox-assistctl" in s
    assert "ALL=(ALL) NOPASSWD: ALL" not in s


def test_units_run_as_non_root():
    svc = (ROOT / "systemd" / "secubox-assist.service").read_text()
    assert "User=secubox-assist" in svc
    assert "NoNewPrivileges=" in svc


def test_postinst_does_not_chown_shared_parents():
    post = (ROOT / "debian" / "postinst").read_text()
    for parent in ("chown -R secubox-assist /run/secubox",
                   "chown -R secubox-assist /etc/secubox",
                   "chown -R secubox-assist /var/log/secubox"):
        assert parent not in post

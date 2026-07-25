# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_dropin_is_mesh_only_and_default_drop_friendly():
    nft = (ROOT / "nft" / "secubox-assist.nft").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert "0.0.0.0" not in nft


def test_nft_dropin_standalone_table_never_drops():
    # A standalone assist table with `policy drop` on a base chain is a
    # board-wide outage the instant this file loads (SSH, webui, everything
    # not explicitly matched gets dropped) — see secubox-toolbox's
    # nftables.d/secubox-toolbox-wg.nft precedent, which uses `policy accept`
    # for exactly this reason. This table must never be able to drop
    # unrelated traffic.
    nft = (ROOT / "nft" / "secubox-assist.nft").read_text()
    assert "policy drop;" not in nft
    assert "policy accept;" in nft


def test_nft_dropin_installed_at_boot_loaded_path():
    # /etc/secubox/nft.d/ is not included by anything and vanishes on
    # reboot; /etc/nftables.d/*.nft is glob-included by /etc/nftables.conf
    # (see secubox-vortex-firewall's postinst) and is what actually
    # survives reboot.
    install = (ROOT / "debian" / "secubox-assist.install").read_text()
    assert "etc/nftables.d/" in install
    assert "etc/secubox/nft.d" not in install


def test_sudoers_is_scoped_to_assistctl():
    s = (ROOT / "sudoers" / "secubox-assist").read_text()
    assert "/usr/sbin/secubox-assistctl" in s
    assert "ALL=(ALL) NOPASSWD: ALL" not in s


def test_sudoers_principal_is_ws_daemon_user():
    # catalog.py's service.*/config.* actions run `sudo -n
    # /usr/sbin/secubox-assistctl ...` from wsserver.dispatch, which is
    # invoked from assist.daemon.handler under secubox-assist.service's
    # User= (see systemd/secubox-assist.service) — NOT the
    # secubox-assist-api.service/webui user. The sudoers principal must
    # match that user or every privileged action is silently denied.
    s = (ROOT / "sudoers" / "secubox-assist").read_text()
    assert "secubox-assist ALL=(root) NOPASSWD: /usr/sbin/secubox-assistctl" in s


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

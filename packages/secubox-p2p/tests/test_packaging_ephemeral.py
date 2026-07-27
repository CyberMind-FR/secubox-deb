# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_sudoers_scoped_exact():
    s = (ROOT / "sudoers" / "secubox-p2p-ephemeral").read_text()
    assert "/usr/sbin/secubox-p2pctl" in s and "NOPASSWD: ALL" not in s and "*" not in s


def test_sudoers_exact_line():
    s = (ROOT / "sudoers" / "secubox-p2p-ephemeral").read_text()
    assert "secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-p2pctl" in s


def test_sweep_units_present():
    svc = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.service").read_text()
    tmr = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.timer").read_text()
    assert "secubox-p2pctl sweep" in svc and "OnUnitActiveSec" in tmr


def test_sweep_service_is_root_oneshot():
    svc = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.service").read_text()
    assert "Type=oneshot" in svc
    assert "User=secubox" not in svc


def test_sweep_timer_install_and_cadence():
    tmr = (ROOT / "systemd" / "secubox-p2p-ephemeral-sweep.timer").read_text()
    assert "OnUnitActiveSec=60s" in tmr
    assert "OnBootSec=" in tmr
    assert "WantedBy=timers.target" in tmr


def test_nft_own_table_policy_accept():
    n = (ROOT / "nft" / "secubox-p2p-ephemeral.nft").read_text()
    assert "51825" in n and "policy accept" in n and "flush ruleset" not in n


def test_nft_is_own_table_never_the_main_firewall():
    n = (ROOT / "nft" / "secubox-p2p-ephemeral.nft").read_text()
    assert "table inet secubox_p2p_ephemeral" in n
    assert "policy drop;" not in n


def test_postinst_no_shared_parent_chown_and_key_guarded():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox /run/secubox", "chown -R secubox /etc/secubox",
                "chown -R secubox /var/lib/secubox"):
        assert bad not in p
    assert "wg genkey" in p and "#DEBHELPER#" in p


def test_postinst_key_generation_is_guarded_idempotent():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "/etc/secubox/secrets/p2p/wg-ephemeral.key" in p
    assert "if [ ! -f /etc/secubox/secrets/p2p/wg-ephemeral.key ]" in p


def test_postinst_enables_sweep_timer_and_reloads_nft():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "secubox-p2p-ephemeral-sweep.timer" in p
    assert "secubox-p2p-ephemeral.nft" in p


def test_rules_installs_ctl_units_sudoers_nft():
    r = (ROOT / "debian" / "rules").read_text()
    assert "secubox-p2pctl" in r
    assert "secubox-p2p-ephemeral-sweep.service" in r or "systemd/*.service" in r
    assert "secubox-p2p-ephemeral" in r
    assert "secubox-p2p-ephemeral.nft" in r

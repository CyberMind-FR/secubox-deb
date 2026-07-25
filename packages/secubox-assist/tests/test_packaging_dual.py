# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_covers_ephemeral_iface_mesh_only():
    nft = (ROOT / "nft" / "secubox-assist.nft").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert 'iifname "wg-ephemeral"' in nft
    assert "0.0.0.0" not in nft
    assert "policy drop" not in nft  # never a standalone drop table


def test_install_ships_the_marketplace_and_escalate_modules():
    # rendezvous.py (OFFER/REQUEST/MATCH_ACCEPT), joinlink.py (single-use
    # join links) and escalate.py (ephemeral identity + wg-ephemeral peer)
    # must actually reach the .deb, not just live in the source tree.
    install = (ROOT / "debian" / "secubox-assist.install").read_text()
    assert "assist/*.py" in install
    for mod in ("rendezvous.py", "joinlink.py", "escalate.py"):
        assert (ROOT / "assist" / mod).exists(), f"{mod} missing from source tree"


def test_control_depends_on_secubox_p2p_for_ephemeral_peers():
    # escalate.add_ephemeral_peer()/teardown() shell out to secubox-p2pctl —
    # the escalate flow is unusable without secubox-p2p installed.
    control = (ROOT / "debian" / "control").read_text()
    assert "secubox-p2p" in control


def test_sudoers_still_scoped_to_assistctl_only():
    s = (ROOT / "sudoers" / "secubox-assist").read_text()
    assert "secubox-assist ALL=(root) NOPASSWD: /usr/sbin/secubox-assistctl" in s
    assert "ALL=(ALL) NOPASSWD: ALL" not in s


def test_postinst_ephemeral_range_block_is_guarded_and_never_invents_a_binary():
    # secubox-p2p has no ephemeral-iface CLI yet (documented follow-up).
    # The provisioning block must be conditioned on the binary actually
    # existing, and must not create/ship a secubox-p2pctl of its own.
    post = (ROOT / "debian" / "postinst").read_text()
    assert "10.11.0.0/24" in post
    assert "wg-ephemeral" in post
    assert "if [ -x /usr/sbin/secubox-p2pctl ]" in post
    assert not (ROOT / "sbin" / "secubox-p2pctl").exists()
    assert not (ROOT / "debian" / "secubox-p2pctl").exists()


def test_postinst_does_not_chown_shared_parents():
    post = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox-assist /run/secubox",
                "chown -R secubox-assist /etc/secubox",
                "chown -R secubox-assist /var/log/secubox",
                "chown /etc/secubox",
                "chown -R /etc/secubox"):
        assert bad not in post


def test_postinst_ephemeral_block_only_touches_its_own_subdirectory():
    # Only /etc/secubox/assist/ (this package's own subdir) is written to —
    # the shared /etc/secubox parent itself is never chmod'd/chown'd.
    post = (ROOT / "debian" / "postinst").read_text()
    assert "mkdir -p /etc/secubox/assist" in post
    assert "chmod 0755 /etc/secubox\n" not in post
    assert "chmod -R /etc/secubox" not in post


def test_changelog_bumped_to_0_2_0():
    changelog = (ROOT / "debian" / "changelog").read_text()
    assert changelog.startswith("secubox-assist (0.2.0-1~bookworm1)")

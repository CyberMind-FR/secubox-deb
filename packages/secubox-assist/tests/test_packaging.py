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


def test_ws_daemon_unit_allows_scoped_sudo_catalog_exec():
    # catalog.resolve() returns `sudo -n /usr/sbin/secubox-assistctl ...` for
    # service/config actions, run by THIS unit (secubox-assist.service, see
    # test_sudoers_principal_is_ws_daemon_user). NoNewPrivileges=true blocks
    # sudo's setuid transition outright, so every privileged catalog action
    # silently fails end-to-end. This unit needs NNP=false; other hardening
    # (ProtectSystem=strict, empty AmbientCapabilities=) stays intact.
    svc = (ROOT / "systemd" / "secubox-assist.service").read_text()
    assert "NoNewPrivileges=false" in svc
    assert "ProtectSystem=strict" in svc
    assert "AmbientCapabilities=" in svc


def test_api_unit_keeps_no_new_privileges_true():
    # The API unit never sudoes (it delegates mutations to ctl via
    # subprocess, invoked as itself, not via sudo) — it keeps full NNP
    # hardening.
    svc = (ROOT / "systemd" / "secubox-assist-api.service").read_text()
    assert "NoNewPrivileges=true" in svc


def test_console_buttons_are_disabled_and_labelled_not_yet_available():
    # console.py (guard + pty + keystroke audit) exists but nothing in the
    # data-plane opens a pty; nothing consumes the CONSOLE_GRANT/REVOKE ops
    # these buttons write. Ship the control-plane honestly: the buttons must
    # not look like a live, working escalation channel.
    html = (ROOT / "www" / "assist" / "index.html").read_text()
    grant_line = next(l for l in html.splitlines() if 'data-act="console-grant"' in l)
    revoke_line = next(l for l in html.splitlines() if 'data-act="console-revoke"' in l)
    assert "disabled" in grant_line
    assert "disabled" in revoke_line
    assert "à venir" in grant_line or "en cours" in grant_line
    assert "à venir" in revoke_line or "en cours" in revoke_line


def test_postinst_does_not_chown_shared_parents():
    post = (ROOT / "debian" / "postinst").read_text()
    for parent in ("chown -R secubox-assist /run/secubox",
                   "chown -R secubox-assist /etc/secubox",
                   "chown -R secubox-assist /var/log/secubox"):
        assert parent not in post


def test_postinst_derives_public_node_did_guarded_and_never_fails():
    # The WS daemon (User=secubox-assist, not in group secubox) must never
    # open the sovereign private key. postinst runs as root and CAN read it,
    # so it derives the DID once here and publishes it world-readable. A
    # missing key (annuairectl init not yet run) must not fail the install.
    post = (ROOT / "debian" / "postinst").read_text()
    assert "/etc/secubox/secrets/annuaire/node.key" in post
    assert "did_from_pubkey" in post and "public_from_private" in post
    assert "/etc/secubox/annuaire/node.did" in post
    assert "chmod 0644 /etc/secubox/annuaire/node.did" in post
    # guarded: reading the key is conditioned on it existing, not assumed
    assert "if [ -r /etc/secubox/secrets/annuaire/node.key ]" in post


def test_postinst_node_did_derivation_does_not_chmod_the_shared_parent():
    # Only the FILE gets a mode; /etc/secubox/annuaire itself (shared with
    # other consumers) must not be chmod'd/chown'd by this package.
    post = (ROOT / "debian" / "postinst").read_text()
    assert "chmod -R" not in post
    for bad in ("chown /etc/secubox/annuaire", "chown -R /etc/secubox/annuaire",
                "chmod 0755 /etc/secubox/annuaire", "chmod -R /etc/secubox/annuaire",
                "chmod 0644 /etc/secubox/annuaire\n"):
        assert bad not in post

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_sudoers_scoped():
    s = (ROOT / "sudoers" / "secubox-release").read_text()
    assert "/usr/sbin/secubox-releasectl" in s
    assert "NOPASSWD: ALL" not in s


def test_sudoers_principal_is_api_user():
    # The release module has a single runtime (secubox-release-api.service,
    # User=secubox) — no separate WS daemon like secubox-assist. The scoped
    # grant's principal must match that unit's User=.
    s = (ROOT / "sudoers" / "secubox-release").read_text()
    assert "secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-releasectl" in s


def test_api_unit_non_root_preserve_runtime():
    u = (ROOT / "systemd" / "secubox-release-api.service").read_text()
    assert "User=secubox" in u and "RuntimeDirectoryPreserve=yes" in u


def test_api_unit_socket_and_hardening():
    u = (ROOT / "systemd" / "secubox-release-api.service").read_text()
    assert "/run/secubox/release.sock" in u
    assert "RuntimeDirectory=secubox" in u
    assert "NoNewPrivileges=true" in u


def test_postinst_no_shared_parent_chown():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox /run/secubox", "chown -R secubox /etc/secubox",
                "chown -R secubox /data/apt"):
        assert bad not in p


def test_postinst_never_touches_apt_host_reprepro_conf():
    # The ring distributions (draft/internal/published) are provisioned on
    # the apt host separately — a package postinst runs on boxes, not the
    # repo host, and must never edit repo-host state.
    p = (ROOT / "debian" / "postinst").read_text()
    assert "/data/apt/conf" not in p


def test_postinst_grants_ctl_traversal_to_signing_key():
    # secubox-releasectl runs as `secubox` (invoked directly by the API, no
    # sudo in that path) and must reach /etc/secubox/secrets/annuaire/node.key
    # to sign publish/promote/demote/assign journal ops — same traversal fix
    # shipped by secubox-assist 0.2.1. Guarded: only chmod o+x if the shared
    # parent exists; never chown/tighten it.
    p = (ROOT / "debian" / "postinst").read_text()
    assert "chmod o+x /etc/secubox/secrets" in p
    assert "if [ -d /etc/secubox/secrets ]" in p


def test_postinst_enables_api_service():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "daemon-reload" in p
    assert "enable --now secubox-release-api.service" in p


def test_install_ships_key_paths():
    inst = (ROOT / "debian" / "secubox-release.install").read_text()
    assert "usr/sbin/" in inst
    assert "usr/share/secubox/www/releases/" in inst
    assert "lib/systemd/system/" in inst
    assert "etc/sudoers.d/" in inst
    assert "etc/nginx/secubox.d/" in inst
    assert "usr/share/secubox/menu.d/" in inst

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-antirootkit :: packaging tests (Task 11)

Reads the debian/ files as text and asserts their content. Never invokes
dpkg-buildpackage or apt — packaging correctness is checked structurally.
"""

import re
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent.parent
DEBIAN = PKG_ROOT / "debian"


def _read(relpath: str) -> str:
    return (PKG_ROOT / relpath).read_text()


def test_control_depends_and_recommends():
    control = _read("debian/control")
    m = re.search(r"^Depends:\s*(.+)$", control, re.MULTILINE)
    assert m, "control has no Depends field"
    depends = m.group(1)
    assert "auditd" in depends
    assert "debsums" in depends

    m = re.search(r"^Recommends:\s*(.+)$", control, re.MULTILINE)
    assert m, "control has no Recommends field"
    assert "aide" in m.group(1)


def test_control_package_metadata():
    control = _read("debian/control")
    assert "Source: secubox-antirootkit" in control
    assert "Package: secubox-antirootkit" in control
    assert "Architecture: all" in control
    assert "Standards-Version: 4.6.2" in control
    assert "Section: admin" in control


def test_postinst_creates_module_dir_without_chowning_shared_parent():
    postinst = _read("debian/postinst")
    assert "install -d" in postinst
    assert "/var/lib/secubox/antirootkit" in postinst

    # Only inspect actual shell code, not prose in comments (a comment
    # explaining "never chown /var/lib/secubox" must not itself trip the
    # check below).
    code_lines = []
    for line in postinst.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        code_lines.append(line.split(" #", 1)[0])
    code = "\n".join(code_lines)

    # NEVER chown a shared parent directory (bare, no module subdir).
    forbidden_parents = [
        r"chown\s+\S+\s+/var/lib/secubox(?:\s|$)",
        r"chown\s+\S+\s+/run/secubox(?:\s|$)",
        r"chown\s+\S+\s+/etc/secubox(?:\s|$)",
    ]
    for pattern in forbidden_parents:
        assert not re.search(pattern, code, re.MULTILINE), (
            f"postinst must never chown a shared parent (matched {pattern!r})"
        )


def test_postinst_creates_system_user():
    postinst = _read("debian/postinst")
    assert "secubox-antirootkit" in postinst
    assert "adduser" in postinst


def test_postinst_loads_nft_and_audit_rules():
    postinst = _read("debian/postinst")
    assert "nft-load" in postinst
    assert "augenrules" in postinst


def test_postinst_has_debhelper_token():
    postinst = _read("debian/postinst")
    assert "#DEBHELPER#" in postinst


def test_prerm_postrm_have_debhelper_token():
    assert "#DEBHELPER#" in _read("debian/prerm")
    assert "#DEBHELPER#" in _read("debian/postrm")


def test_rules_installs_nft_sudoers_and_audit_files():
    rules = _read("debian/rules")
    assert "secubox-antiescape.nft" in rules
    assert "sudoers/secubox-antirootkit" in rules
    assert "99-sbx-procwatch.rules" in rules
    assert "secubox-antirootkitctl" in rules


def test_audit_rule_file_targeted_watches():
    rules = _read("conf/99-sbx-procwatch.rules")
    assert "-p x" in rules
    assert "sbx_exec" in rules
    for path in (
        "/usr/local/bin",
        "/usr/local/sbin",
        "/tmp",
        "/dev/shm",
        "/opt",
        "/usr/lib/jvm",
    ):
        assert path in rules


def test_compat_level_13():
    compat = _read("debian/compat").strip()
    assert compat == "13"


def test_service_units_present_and_wired():
    api_service = _read("debian/secubox-antirootkit.service")
    assert "User=secubox-antirootkit" in api_service
    assert "RuntimeDirectory=secubox" in api_service
    assert "RuntimeDirectoryPreserve=yes" in api_service
    assert "/run/secubox/antirootkit.sock" in api_service

    watcher_service = _read("systemd/sbx-antirootkitd.service")
    assert "User=secubox-antirootkit" in watcher_service


def test_slice_is_top_level_not_nested():
    slice_unit = _read("systemd/sbx-untrusted.slice")
    assert "[Slice]" in slice_unit
    # Must not declare itself as part of another slice (top-level cgroup).
    assert "Slice=" not in slice_unit


def test_changelog_version_and_distribution():
    changelog = _read("debian/changelog")
    assert changelog.startswith("secubox-antirootkit (0.1.0-1~bookworm1) bookworm;")
    assert "Gérald Kerma <devel@cybermind.fr>" in changelog

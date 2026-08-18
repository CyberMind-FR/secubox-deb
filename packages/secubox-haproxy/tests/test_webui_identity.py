# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: webui_identity tests
Author: Gerald KERMA <devel@cybermind.fr>
"""
import os
import textwrap
import pytest
from pathlib import Path

from api import webui_identity as wi


@pytest.fixture(autouse=True)
def _reset_cache():
    wi.invalidate_cache()
    yield
    wi.invalidate_cache()


def _write_defaults(tmp_path, body):
    p = tmp_path / "secubox"
    p.write_text(textwrap.dedent(body))
    return p


def test_parse_basic(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="gk2"
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["hostname"] == "gk2"
    assert ident["domain_suffix"] == "secubox.in"
    assert ident["admin_domain"] == "admin.gk2.secubox.in"
    assert ident["regex"] == r"^admin\.gk2\.secubox\.in$"


def test_missing_hostname_raises(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    with pytest.raises(ValueError, match="SECUBOX_HOSTNAME"):
        wi.get_identity()


def test_custom_suffix(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="mochabin"
        SECUBOX_DOMAIN_SUFFIX="lan.local"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["admin_domain"] == "admin.mochabin.lan.local"
    assert ident["regex"] == r"^admin\.mochabin\.lan\.local$"


def test_comments_and_blank_lines(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        # comment
        SECUBOX_HOSTNAME="gk2"

        # another comment
        SECUBOX_DOMAIN_SUFFIX="secubox.in"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    ident = wi.get_identity()
    assert ident["hostname"] == "gk2"


def test_invalidate_cache(monkeypatch, tmp_path):
    p = _write_defaults(tmp_path, """\
        SECUBOX_HOSTNAME="gk2"
    """)
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    first = wi.get_identity()
    p.write_text('SECUBOX_HOSTNAME="changed"\n')
    cached = wi.get_identity()
    assert cached["hostname"] == "gk2"  # cache hit
    wi.invalidate_cache()
    refreshed = wi.get_identity()
    assert refreshed["hostname"] == "changed"


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses chmod 000")
def test_unreadable_file_returns_empty_then_raises(monkeypatch, tmp_path):
    """If the defaults file exists but is unreadable, get_identity raises ValueError."""
    p = tmp_path / "secubox-unreadable"
    p.write_text('SECUBOX_HOSTNAME="gk2"\n')
    p.chmod(0o000)  # No read permission for anyone
    monkeypatch.setattr(wi, "DEFAULTS_FILE", p)
    try:
        # Should NOT raise OSError/PermissionError directly;
        # instead, get_identity raises ValueError because HOSTNAME is unset.
        with pytest.raises(ValueError, match="SECUBOX_HOSTNAME"):
            wi.get_identity()
    finally:
        # Restore permissions so the temp file can be cleaned up
        p.chmod(0o644)

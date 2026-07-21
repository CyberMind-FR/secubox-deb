# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests édition du niveau d'éveil dans un manifeste
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import stat

import pytest

_MANIFEST = (
    'id        = "yacy"\n'
    'category  = "infra"\n'
    'runtime   = "lxc"\n'
    'units     = ["secubox-yacy.service"]\n'
    'lxc       = "yacy"\n'
    'portal    = { domain = "yacy.gk2.secubox.in" }\n'
    'priority  = 50\n'
    'exposure  = "public"\n'
    'protected = false\n'
    '\n'
    'lifecycle = "on-demand"\n'
)


def _load(path):
    from api.manifest import load_manifest
    return load_manifest(path)


def test_replaces_existing_lifecycle_and_appends_missing_wake_class(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "yacy.toml"
    p.write_text(_MANIFEST)
    set_lifecycle(p, lifecycle="always-on", wake_class="urgent")
    m = _load(p)
    assert m.lifecycle == "always-on"
    assert m.wake_class == "urgent"
    # everything else preserved
    assert m.id == "yacy" and m.lxc == "yacy" and m.priority == 50
    assert m.portal_domain == "yacy.gk2.secubox.in"


def test_preserves_comments_and_other_lines(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('# derived by scan\nid = "m"\ncategory="infra"\nruntime="native"\nexposure="lan"\n'
                 'units=["m.service"]\nlifecycle = "eager"  # was manual\n')
    set_lifecycle(p, lifecycle="on-demand", wake_class="normal")
    text = p.read_text()
    assert "# derived by scan" in text
    assert 'lifecycle = "on-demand"' in text
    assert 'lifecycle = "eager"' not in text
    m = _load(p)
    assert m.lifecycle == "on-demand" and m.wake_class == "normal"


def test_replaces_both_when_both_present(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n'
                 'lifecycle = "manual"\nwake_class = "normal"\n')
    set_lifecycle(p, lifecycle="on-demand", wake_class="urgent")
    m = _load(p)
    assert m.lifecycle == "on-demand" and m.wake_class == "urgent"
    # no duplicate key lines left behind
    assert p.read_text().count("wake_class") == 1
    assert p.read_text().count("lifecycle") == 1


def test_rejects_invalid_lifecycle(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n')
    with pytest.raises(ValueError):
        set_lifecycle(p, lifecycle="turbo", wake_class="normal")
    with pytest.raises(ValueError):
        set_lifecycle(p, lifecycle="on-demand", wake_class="panic")


def test_rejects_manifest_with_section_header(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n'
                 '[portal]\ndomain = "m.gk2"\n')
    with pytest.raises(ValueError):
        set_lifecycle(p, lifecycle="on-demand", wake_class="normal")


def test_preserves_file_mode(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n'
                 'lifecycle="manual"\n')
    p.chmod(0o644)
    set_lifecycle(p, lifecycle="eager", wake_class="normal")
    assert stat.S_IMODE(p.stat().st_mode) == 0o644


def test_collapses_duplicate_same_key(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n'
                 'lifecycle = "manual"\nlifecycle = "eager"\n')
    set_lifecycle(p, lifecycle="on-demand", wake_class="normal")
    assert p.read_text().count("lifecycle") == 1
    m = _load(p)
    assert m.lifecycle == "on-demand"


def test_handles_no_trailing_newline(tmp_path):
    from api.manifest_edit import set_lifecycle
    p = tmp_path / "m.toml"
    p.write_text('id="m"\ncategory="infra"\nruntime="native"\nexposure="lan"\nunits=["m.service"]\n'
                 'lifecycle = "manual"')  # no trailing newline
    set_lifecycle(p, lifecycle="eager", wake_class="urgent")
    m = _load(p)
    assert m.lifecycle == "eager" and m.wake_class == "urgent"
    assert p.read_text().endswith("\n")

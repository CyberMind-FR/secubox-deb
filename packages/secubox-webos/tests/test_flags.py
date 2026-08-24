# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — lecture flags webos.toml (api.flags.load_flags)."""
from api.flags import load_flags


def test_missing_file_defaults(tmp_path):
    f = load_flags(str(tmp_path / "nope.toml"))
    assert f == {"enabled": False, "registry_enabled": True}


def test_reads_enabled(tmp_path):
    p = tmp_path / "webos.toml"
    p.write_text("[webos]\nenabled = true\nregistry_enabled = false\n")
    assert load_flags(str(p)) == {"enabled": True, "registry_enabled": False}

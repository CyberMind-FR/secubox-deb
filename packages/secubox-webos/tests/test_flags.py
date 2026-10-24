# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — lecture flags webos.toml (api.flags.load_flags)."""
from api.flags import load_flags


def test_missing_file_defaults(tmp_path):
    f = load_flags(str(tmp_path / "nope.toml"))
    assert f == {"enabled": False, "registry_enabled": True, "hall_v2": True}


def test_reads_enabled(tmp_path):
    p = tmp_path / "webos.toml"
    p.write_text("[webos]\nenabled = true\nregistry_enabled = false\n")
    assert load_flags(str(p)) == {"enabled": True, "registry_enabled": False, "hall_v2": True}


def test_hall_v2_est_un_flag_a_part_entiere(tmp_path):
    p = tmp_path / "webos.toml"
    p.write_text("[webos]\nenabled = true\nhall_v2 = true\n")
    assert load_flags(str(p))["hall_v2"] is True


def test_hall_v2_par_defaut_et_retour_arriere_explicite(tmp_path):
    # #3115 : le Hall v2 (vue maître Aurora) est le défaut ; « hall_v2 = false » reste le retour arrière.
    p = tmp_path / "webos.toml"
    p.write_text("[webos]\nenabled = true\n")
    assert load_flags(str(p))["hall_v2"] is True
    p.write_text("[webos]\nhall_v2 = false\n")
    assert load_flags(str(p))["hall_v2"] is False

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

import pytest

from api.state import load_profile

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"
PROFILE_FILES = sorted(PROFILES_DIR.glob("*.toml"))
EXPECTED = {"full", "lite", "secure-gateway", "media-lab", "minimal"}


def test_all_profiles_ship():
    assert {p.stem for p in PROFILE_FILES} == EXPECTED


@pytest.mark.parametrize("path", PROFILE_FILES, ids=lambda p: p.stem)
def test_profile_loads_and_name_matches_stem(path):
    prof = load_profile(path)          # raises StateError if name != stem or bad 'on'
    assert prof.name == path.stem
    assert prof.on, f"{path.stem}: empty on-list"
    for mid in prof.on:
        assert mid and mid == mid.strip() and " " not in mid, f"bad id {mid!r}"


def test_protected_core_present_in_every_profile():
    # aggregator/auth/core are protected (always ON) but every functional tier
    # lists them explicitly for readability; guard that nobody drops them.
    for path in PROFILE_FILES:
        on = load_profile(path).on
        assert {"core", "auth", "aggregator"} <= on, f"{path.stem} missing protected"


# `minimal` (#2838) est une box SANS ECRAN (ESPRESSObin) : ni kiosque, ni console locale, par construction (secubox-minimal n'installe ni l'un ni l'autre).
SANS_ECRAN = {"minimal"}


@pytest.mark.parametrize("path", [p for p in PROFILE_FILES if p.stem not in SANS_ECRAN], ids=lambda p: p.stem)
def test_chaque_profil_porte_le_kiosque_et_la_console(path):
    """#2332 : le kiosque WebUI (écran) et la console TUI (sa partie headless) sont les deux visages locaux de la box : dans tous les profils AVEC écran."""
    assert {"kiosk", "console"} <= load_profile(path).on, path.stem


def test_un_profil_sans_ecran_n_allume_ni_kiosque_ni_console():
    for stem in SANS_ECRAN:
        on = load_profile(PROFILES_DIR / f"{stem}.toml").on
        assert not ({"kiosk", "console"} & on), stem

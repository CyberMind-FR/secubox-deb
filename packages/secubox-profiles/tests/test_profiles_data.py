# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

import pytest

from api.state import load_profile

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"
PROFILE_FILES = sorted(PROFILES_DIR.glob("*.toml"))
EXPECTED = {"full", "lite", "secure-gateway", "media-lab"}


def test_all_four_profiles_ship():
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

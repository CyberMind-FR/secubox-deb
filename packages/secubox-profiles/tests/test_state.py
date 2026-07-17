# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.manifest import Manifest
from api.state import Profile, StateError, load_pins, load_profile, resolve


def mk(mid, protected=False):
    return Manifest(id=mid, category="media", runtime="native", exposure="lan",
                    units=(f"secubox-{mid}.service",), protected=protected)


MEDIA = Profile(name="media", label="🎬 Média", on=frozenset({"lyrion", "peertube"}))


def test_listed_in_profile_is_on():
    assert resolve(mk("lyrion"), MEDIA, {}) == "on"


def test_not_listed_is_off():
    # Profil exhaustif : ce qui n'est pas listé est éteint.
    assert resolve(mk("gitea"), MEDIA, {}) == "off"


def test_pin_on_beats_profile_off():
    assert resolve(mk("gitea"), MEDIA, {"gitea": "on"}) == "on"


def test_pin_off_beats_profile_on():
    assert resolve(mk("lyrion"), MEDIA, {"lyrion": "off"}) == "off"


def test_protected_beats_pin_off():
    # Non négociable : sans ça, un pin peut verrouiller l'utilisateur
    # hors de sa propre box.
    assert resolve(mk("auth", protected=True), MEDIA, {"auth": "off"}) == "on"


def test_protected_beats_profile_omission():
    assert resolve(mk("auth", protected=True), MEDIA, {}) == "on"


def test_no_profile_means_only_pins_and_protected():
    # Aucun profil actif : on n'éteint rien de protégé, et les pins valent.
    assert resolve(mk("auth", protected=True), None, {}) == "on"
    assert resolve(mk("gitea"), None, {"gitea": "on"}) == "on"
    assert resolve(mk("gitea"), None, {}) == "off"


def test_load_profile(tmp_path):
    p = tmp_path / "media.toml"
    p.write_text('name = "media"\nlabel = "🎬 Média"\non = ["lyrion", "peertube"]\n')
    prof = load_profile(p)
    assert prof.name == "media" and prof.label == "🎬 Média"
    assert prof.on == frozenset({"lyrion", "peertube"})


def test_load_profile_rejects_name_mismatch(tmp_path):
    p = tmp_path / "media.toml"
    p.write_text('name = "autre"\nlabel = "x"\non = []\n')
    with pytest.raises(StateError):
        load_profile(p)


def test_load_pins(tmp_path):
    p = tmp_path / "pins.toml"
    p.write_text('gitea = "on"\ndpi = "off"\n')
    assert load_pins(p) == {"gitea": "on", "dpi": "off"}


def test_load_pins_missing_file_is_empty(tmp_path):
    # Pas de pins = cas normal, pas une erreur.
    assert load_pins(tmp_path / "absent.toml") == {}


def test_load_pins_rejects_bad_value(tmp_path):
    p = tmp_path / "pins.toml"
    p.write_text('gitea = "maybe"\n')
    with pytest.raises(StateError):
        load_pins(p)

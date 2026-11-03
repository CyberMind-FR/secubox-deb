# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Image dédiée rpi4-dsi (ref #3426) : cible CI, nom distinct, notes de release."""
import fnmatch
from pathlib import Path

import yaml

RACINE = Path(__file__).resolve().parents[1]
WF = RACINE / ".github" / "workflows"


def _matrice():
    d = yaml.safe_load((WF / "build-all-live-usb.yml").read_text())
    return {e["platform"]: e for e in d["jobs"]["build-live-usb"]["strategy"]["matrix"]["include"]}


def test_yaml_valides():
    for f in ("build-all-live-usb.yml", "release.yml", "build-image.yml"):
        yaml.safe_load((WF / f).read_text())


def test_cible_rpi4_dsi_kiosque_et_dsi():
    e = _matrice()["rpi4-dsi"]
    assert e["script"] == "build-rpi-usb.sh"
    args = e["extra_args"].split()
    assert "--kiosk" in args and "--rpi-dsi" in args


def test_noms_distincts_de_rpi400():
    m = _matrice()
    assert m["rpi4-dsi"]["artifact_name"] != m["rpi400"]["artifact_name"]
    assert m["rpi4-dsi"]["output_pattern"] != m["rpi400"]["output_pattern"]
    dsi = "secubox-full-rpi4-dsi-arm64-trixie.img.gz"
    hdmi = "secubox-full-rpi-arm64-trixie.img.gz"
    assert fnmatch.fnmatch(dsi, m["rpi4-dsi"]["output_pattern"])
    assert not fnmatch.fnmatch(dsi, m["rpi400"]["output_pattern"])
    assert not fnmatch.fnmatch(hdmi, m["rpi4-dsi"]["output_pattern"])


def test_le_script_nomme_l_image_dsi_a_part():
    s = (RACINE / "image" / "build-rpi-usb.sh").read_text()
    assert 'IMG_FAMILLE="rpi4-dsi-arm64"' in s
    assert '${PROFILE_TAG}-${IMG_FAMILLE}-${SUITE}.img' in s


def test_choix_manuel_et_notes_de_release():
    d = yaml.safe_load((WF / "build-all-live-usb.yml").read_text())
    opts = d[True]["workflow_dispatch"]["inputs"]["platform"]["options"] if True in d else d["on"]["workflow_dispatch"]["inputs"]["platform"]["options"]
    assert "rpi4-dsi" in opts
    rel = (WF / "release.yml").read_text()
    assert "rpi4-dsi" in rel and "écran officiel 7" in rel and "écran HDMI" in rel

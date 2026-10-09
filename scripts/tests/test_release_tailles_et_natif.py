# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les échecs de la release alpha.10 qui n'étaient ni des profils ni des paquets (#2146, #2020)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]


def test_la_live_usb_mochabin_a_la_place_de_son_systeme():
    """4G ne contenait pas le système (≈ 4,4 Go) : rsync « No space left on device » à 85 %."""
    t = (RACINE / "image" / "build-mochabin-live-usb.sh").read_text(encoding="utf-8")
    m = re.search(r'^IMG_SIZE="(\d+)G"', t, re.M)
    assert m and int(m.group(1)) >= 8


def test_voice_moteur_arm64_se_construit_en_natif_comme_ndpid_engine():
    """Il compile whisper-cli (g++, cmake) : la voie croisée `-a arm64` échouait sur « Unmet build dependencies: g++ »."""
    w = (RACINE / ".github" / "workflows" / "build-packages.yml").read_text(encoding="utf-8")
    natif = re.search(r'NATIF_ARM64="([^"]*)"', w).group(1).split()
    assert "secubox-voice-moteur" in natif and "secubox-ndpid-engine" in natif
    qemu = w.split("Setup QEMU (build arm64 natif emule)")[1].split("uses:")[0]
    assert "secubox-voice-moteur" in qemu
    conteneur = w.split("bash -c 'set -e")[1].split("dpkg-buildpackage")[0]
    for outil in ("curl", "python3", "git", "cmake"):
        assert outil in conteneur, outil

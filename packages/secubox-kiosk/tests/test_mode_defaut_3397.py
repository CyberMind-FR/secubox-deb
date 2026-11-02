# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mode par défaut du kiosque (ref #3397) : Wayland sur RPi et autres ARM, X11 seulement sur amd64 et en virtualisation."""
import re
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-kiosk-setup"


def _fonctions() -> str:
    t = SCRIPT.read_text()
    return "\n".join(re.search(rf"^{n}\(\) {{\n.*?^}}$", t, re.S | re.M).group(0) for n in ("detect_vm", "default_mode"))


def _mode(tmp_path, arch: str, virt: str) -> str:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "dpkg").write_text(f"#!/bin/sh\necho {arch}\n")
    (stubs / "systemd-detect-virt").write_text(f"#!/bin/sh\n[ \"$1\" = -q ] || echo {virt}\n[ {virt} != none ]\n")
    for f in stubs.iterdir():
        f.chmod(0o755)
    r = subprocess.run(["bash", "-c", _fonctions() + "\ndefault_mode"], capture_output=True, text=True,
                       env={"PATH": f"{stubs}:/usr/bin:/bin"})
    return r.stdout.strip()


@pytest.mark.parametrize("arch,virt,attendu", [
    ("arm64", "none", "wayland"),     # RPi4, RPi400
    ("armhf", "none", "wayland"),
    ("amd64", "none", "x11"),
    ("arm64", "kvm", "x11"),          # virtualisation : X11 quelle que soit l'architecture
    ("amd64", "qemu", "x11"),
])
def test_mode_par_defaut(tmp_path, arch, virt, attendu):
    assert _mode(tmp_path, arch, virt) == attendu


def test_le_defaut_n_est_plus_x11_en_dur():
    t = SCRIPT.read_text()
    assert 'MODE="$(default_mode)"' in t
    assert ':-x11}' not in t

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3480 : une étiquette de bêta construit chaque carte × lite et minimal ; hors bêta, la matrice publiée ne bouge pas."""
import json
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
RELEASE = (RACINE / ".github/workflows/release.yml").read_text(encoding="utf-8")


def _matrice(profil):
    sortie = subprocess.run(
        ["python3", ".github/scripts/matrice-images.py", "--cartes", "defaut", "--profil", profil],
        cwd=RACINE, capture_output=True, text=True, check=True).stdout
    return {(e["board"], e["profile"]) for e in json.loads(sortie)["include"]}


def test_complet_toutes_les_cartes_tous_les_profils():
    m = _matrice("complet")
    assert len(m) == 11
    assert ("espressobin-ultra", "mobile") in m and ("rpi400", "mobile") not in m and ("vm-arm64", "minimal") in m
    assert not {p for _, p in m} & {"isp", "full"}
    assert all((RACINE / "board" / carte).is_dir() for carte, _ in m)


def test_hors_beta_la_matrice_publiee_reste_une_image_par_carte():
    assert _matrice("auto") == {("mochabin", "lite"), ("vm-x64", "lite"), ("rpi400", "lite"), ("espressobin-v7", "minimal")}


def test_etiquette_beta_declenche_le_complet():
    wf = (RACINE / ".github/workflows/build-image.yml").read_text(encoding="utf-8")
    assert "refs/tags/v*-beta*) profil=complet" in wf


def test_release_ne_telecharge_les_images_qu_une_fois():
    assert RELEASE.count("pattern: secubox-*-${{ env.DEBIAN_SUITE }}") == 1
    assert "release-disque.sh" in RELEASE


def test_live_arm64_au_profil_mobile():
    wf = (RACINE / ".github/workflows/build-all-live-usb.yml").read_text(encoding="utf-8")
    assert wf.count('extra_args: "--kiosk --profile mobile"') == 2       # x64, rpi400
    assert 'extra_args: "--kiosk --rpi-dsi --profile mobile"' in wf
    assert 'extra_args: "--size 8G --profile mobile"' in wf               # ESPRESSObin
    assert 'extra_args: "--profile mobile"' in wf                        # MOCHAbin, sans écran
    moch = (RACINE / "image/build-mochabin-live-usb.sh").read_text(encoding="utf-8")
    assert '"${PROFILE_TAG}" "${ROOTFS}/tmp/debs" arm64' in moch and "non installé dans l'image" in moch
    assert "lite|minimal|mobile|isp|full) ;;" in (RACINE / "image/build-rpi-usb.sh").read_text(encoding="utf-8")

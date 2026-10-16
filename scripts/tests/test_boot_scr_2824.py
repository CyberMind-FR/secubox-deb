# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2824 — une image ESPRESSObin sans boot.scr ni boot-usb.scr n'est pas une image : la CI n'installait pas u-boot-tools, et la construction continuait en avertissement."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
WORKFLOW = (RACINE / ".github" / "workflows" / "build-image.yml").read_text()
BUILD = (RACINE / "image" / "build-image.sh").read_text()


def test_la_ci_installe_u_boot_tools():
    etape = WORKFLOW.split("- name: Install build tools", 1)[1].split("- name:", 1)[0]
    assert "u-boot-tools" in etape


def test_le_script_usb_est_copie_sans_dependre_de_mkimage():
    """Il est livre deja compile : il n'a pas besoin de mkimage pour etre copie."""
    bloc = BUILD.split("# Script USB (#2816, #2824)", 1)[1].split("# Démonter", 1)[0]
    copie = bloc.index('cp "${SCRIPT_DIR}/../board/${BOARD}/boot-usb.scr"')
    ouverture = bloc.index("if command -v mkimage")
    assert copie < ouverture, "la copie de boot-usb.scr doit PRECEDER (et donc ne pas dependre de) le « if mkimage »"


def test_sans_mkimage_une_image_espressobin_echoue():
    bloc = BUILD.split("# Compiler le bootscript si mkimage est disponible", 1)[1].split("# Démonter", 1)[0]
    assert re.search(r'espressobin\*.*err ', bloc, re.S) or "err \"mkimage" in bloc, "mkimage absent : avertissement seulement"

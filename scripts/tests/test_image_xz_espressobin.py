# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""L'image ESPRESSObin lite se publie : en .img.xz, sous les 2 Gio d'un fichier de release GitHub (#2146).

Le .img.gz de lite pesait 2,07 Gio (2 222 070 817 octets) : l'étape « Create GitHub Release » l'aurait refusé, comme l'image `full`
de la MOCHAbin à l'alpha 9. xz le ramène bien en dessous ; la chaîne (script, carte, workflow) doit donc suivre le suffixe."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
SCRIPT = (RACINE / "image" / "build-image.sh").read_text(encoding="utf-8")
WORKFLOW = (RACINE / ".github" / "workflows" / "build-image.yml").read_text(encoding="utf-8")


def test_les_cartes_espressobin_demandent_xz():
    for carte in ("espressobin-v7", "espressobin-ultra"):
        t = (RACINE / "board" / carte / "config.mk").read_text(encoding="utf-8")
        assert re.search(r"^IMG_COMPRESS=xz\s*$", t, re.M), carte


def test_le_script_sait_compresser_en_xz_et_dit_comment_flasher():
    assert 'IMG_COMPRESS="${IMG_COMPRESS:-gz}"' in SCRIPT
    assert "xz -T0" in SCRIPT and "${IMG_FILE}.xz" in SCRIPT
    assert "xzcat" in SCRIPT


def test_le_workflow_prend_aussi_les_images_xz():
    for ligne in WORKFLOW.splitlines():
        if "*.img.gz" in ligne and "gunzip" not in ligne and "|" not in ligne.replace("| ", "", 1) and "`" not in ligne:
            assert "*.img.xz" in WORKFLOW
    for motif in ("output/*.img.xz", "images/*.img.xz"):
        assert motif in WORKFLOW, motif
    assert "nullglob" in WORKFLOW

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Les parts fixes de l'image ne mangent pas la moitié d'une carte de 8 Go (#2146).

L'image ESPRESSObin vise une carte uSD « 8 Go » : 7168 MiB. Avec ESP 1024 + DATA 1536 (parts d'une image `full` de 12 Go), il restait
4230 MiB de ROOT pour un profil lite de 5010 MiB : « ROOTFS TROP GROSSE », image perdue après trois heures de construction. Sous
8192 MiB les parts sont réduites (ESP 256, DATA 512 : un noyau et son initrd, et un point de montage qui grandit à l'exécution)."""
import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "image" / "build-image.sh"


def parts(img_mib):
    t = SCRIPT.read_text(encoding="utf-8")
    debut = t.index("if (( IMG_MIB <")
    fin = t.index("\nfi\n", debut) + 4
    bloc = re.sub(r"^\s*log .*$", "", t[debut:fin], flags=re.M)
    r = subprocess.run(["bash", "-c", f"IMG_MIB={img_mib}\n{bloc}\necho $ESP_MIB $DATA_MIB"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    esp, data = (int(x) for x in r.stdout.split())
    return esp, data


def test_l_image_de_7168_mio_garde_plus_de_6_gio_pour_root():
    esp, data = parts(7168)
    assert (esp, data) == (256, 512)
    assert 7168 - esp - data >= 6144


def test_les_images_de_8_gio_et_plus_gardent_les_grandes_parts():
    assert parts(8192) == (1024, 1536)
    assert parts(12288) == (1024, 1536)

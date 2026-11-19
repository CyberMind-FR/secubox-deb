# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3826 — l'image live masque des services de modules incomplets ; leur minuterie doit suivre.

Sur gk3, secubox-ui-health.service masqué par l'image (26/09) et sa minuterie restée activée : systemd refusait de la
démarrer (« unit to trigger not loaded ») et le garde des minuteries finissait en échec toutes les 10 min."""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "image" / "build-live-usb.sh"


def _boucle_de_masquage(texte: str) -> str:
    debut = texte.index('for svc in "${INCOMPLETE_MODULES[@]}"; do')
    return texte[debut:texte.index("\ndone\n", debut) + 6]


def test_la_minuterie_d_un_service_masque_est_masquee_aussi(tmp_path):
    boucle = _boucle_de_masquage(SCRIPT.read_text(encoding="utf-8"))
    assert re.search(r"systemctl mask \$\{svc\}\.timer", boucle)
    # Exécution réelle de la boucle avec un faux chroot : seule une minuterie PRÉSENTE est masquée.
    racine = tmp_path / "rootfs"
    (racine / "usr/lib/systemd/system").mkdir(parents=True)
    (racine / "usr/lib/systemd/system/secubox-ui-health.timer").write_text("[Timer]\n")
    faux = tmp_path / "bin"
    faux.mkdir()
    (faux / "chroot").write_text(f'#!/bin/bash\nshift\necho "$*" >> "{tmp_path}/appels"\n')
    (faux / "chroot").chmod(0o755)
    script = (f'set -euo pipefail\nROOTFS="{racine}"\nINCOMPLETE_MODULES=(secubox-ui-health secubox-mail)\n'
              + boucle)
    subprocess.run(["bash", "-c", script], check=True, timeout=30, capture_output=True, text=True,
                   env={"PATH": f"{faux}:/usr/bin:/bin"})
    appels = (tmp_path / "appels").read_text().splitlines()
    assert "systemctl mask secubox-ui-health.timer" in appels
    assert "systemctl disable secubox-ui-health.timer" in appels
    assert "systemctl mask secubox-mail.service" in appels
    assert not [a for a in appels if "secubox-mail.timer" in a]

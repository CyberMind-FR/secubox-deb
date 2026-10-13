# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2534 — le kiosque ouvre l'ADMINISTRATION (admin.localhost), pas le Hall (réalisation personnelle de gk2).

On extrait `determine_url` du vrai lanceur et on la fait tourner avec de faux curl / systemctl / premier-pas-url."""
import os
import re
import subprocess
from pathlib import Path

LANCEUR = Path(__file__).resolve().parents[3] / "image" / "sbin" / "secubox-kiosk-launcher"
TEXTE = LANCEUR.read_text()
DEBUT = TEXTE.index("determine_url() {")
FONCTION = TEXTE[DEBUT:TEXTE.index("\n}\n", DEBUT) + 3]

CURL = r"""#!/bin/bash
# faux curl : repond selon l'hote:port de --resolve ; la page de l'admin n'a pas featgrid, celle du Hall l'a.
url="${@: -1}"
case "$url" in
  http://admin.localhost:9078/*) [ -n "$SANS_ADMIN_9078" ] && exit 7; echo '<title>SecuBox — Dashboard</title>' ;;
  http://admin.localhost:9080/*) [ -n "$SANS_ADMIN_9080" ] && exit 7; echo '<title>SecuBox — Dashboard</title>' ;;
  http://hall.localhost:*) echo '<title>SecuBox Hall</title><div id="featgrid"></div>' ;;
  *) exit 0 ;;
esac
"""


def _url(tmp_path, env_extra=None, premier_pas="", defaults=None):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for nom, corps in (("curl", CURL), ("systemctl", "#!/bin/sh\nexit 0\n"), ("sleep", "#!/bin/sh\nexit 0\n")):
        f = bin_ / nom
        f.write_text(corps)
        f.chmod(0o755)
    pp = tmp_path / "premier-pas-url"
    pp.write_text(f"#!/bin/sh\necho '{premier_pas}'\n")
    pp.chmod(0o755)
    dfl = tmp_path / "kiosk.default"
    dfl.write_text(defaults or "")
    script = (f'log() {{ :; }}\nPREMIER_PAS_URL_BIN={pp}\nKIOSK_DEFAUTS={dfl}\n' + FONCTION.replace("/usr/sbin/premier-pas-url", str(pp))
              + "\ndetermine_url\n")
    env = dict(os.environ, PATH=f"{bin_}:{os.environ['PATH']}", **(env_extra or {}))
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    return p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""


def test_le_kiosque_ouvre_l_administration_sur_la_console_locale(tmp_path):
    assert _url(tmp_path) == "http://admin.localhost:9078/"


def test_repli_sur_le_port_ordinaire_de_l_administration(tmp_path):
    assert _url(tmp_path, {"SANS_ADMIN_9078": "1"}) == "http://admin.localhost:9080/"


def test_assistant_premier_pas_reste_prioritaire(tmp_path):
    assert _url(tmp_path, premier_pas="premier-pas/#abc").endswith("/premier-pas/#abc")


def test_kiosk_start_hall_rend_l_ancien_comportement(tmp_path):
    assert _url(tmp_path, defaults='KIOSK_START="hall"\n') == "http://hall.localhost:9078/"


def test_sans_admin_joignable_on_ne_ferme_pas_la_porte_au_hall(tmp_path):
    assert _url(tmp_path, {"SANS_ADMIN_9078": "1", "SANS_ADMIN_9080": "1"}) == "http://hall.localhost:9078/"

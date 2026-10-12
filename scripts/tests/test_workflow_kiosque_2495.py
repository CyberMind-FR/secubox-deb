# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2495 — le kiosque est la face de la carte RPi400 : par défaut dans les images publiées ; l'audit des dépendances est branché sur la construction RPi."""
import pathlib
import re

import yaml

RACINE = pathlib.Path(__file__).resolve().parents[2]
WF = (RACINE / ".github" / "workflows" / "build-image.yml").read_text(encoding="utf-8")
RPI = (RACINE / "image" / "build-rpi-usb.sh").read_text(encoding="utf-8")


def test_le_declenchement_manuel_propose_auto_par_defaut():
    d = yaml.safe_load(WF)
    entree = (d.get("on") or d.get(True))["workflow_dispatch"]["inputs"]["kiosk"]
    assert entree["type"] == "choice" and entree["default"] == "auto" and set(map(str, entree["options"])) == {"auto", "true", "false"}


def test_rpi_prend_le_kiosque_sauf_refus_explicite():
    m = re.search(r'KIOSK_WANTED="\$\{\{ inputs.kiosk \|\| github.event.inputs.kiosk \}\}"\n\s*case "\$\{\{ matrix.board \}\}" in\n\s*rpi400\|rpi4\) (.*?) ;;\n\s*esac\n\s*if \[ "\$KIOSK_WANTED" = "true" \]; then\n\s*KIOSK_OPT="--kiosk"', WF, re.S)
    assert m, "bloc kiosque introuvable"
    assert 'KIOSK_WANTED=true' in m.group(1) and '"auto"' in m.group(1) and '-z "$KIOSK_WANTED"' in m.group(1)       # vide (push, workflow_call) ou auto -> vrai ; « false » reste faux


def test_la_construction_rpi_resout_puis_audite_les_dependances():
    i = RPI.index("--fix-broken install -y -q --no-install-recommends")
    j = RPI.index("verify-deps.py")
    assert i < j and "|| err" in RPI[j:j + 400]
    assert "skip apt-get -f" not in RPI                         # l'ancien commentaire qui justifiait l'absence de résolution

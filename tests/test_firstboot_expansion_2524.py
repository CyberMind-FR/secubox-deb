# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-firstboot (ref #2524) : l'extension du système de fichiers ne doit jamais arrêter le premier démarrage.

Constaté sur une RPi400 : `parted -s … resizepart` sur la partition montée demande une confirmation, puis `warn` (jamais défini) répond
« command not found » (127) et, sous `set -e`, le script meurt : ni HAProxy, ni nginx 80/443, ni kiosque."""
import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "image" / "firstboot.sh"
TEXTE = SCRIPT.read_text()
AIDES = ("warn", "err", "die", "fail", "error", "info", "debug", "fatal")


def test_syntaxe_valide():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_toute_fonction_d_aide_appelee_est_definie():
    definies = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", TEXTE, re.M))
    appelees = set()
    for ligne in TEXTE.splitlines():
        code = ligne.split("#", 1)[0]
        for nom in AIDES:
            if re.search(rf"(?:^|[;&|(]\s*|\|\|\s*|&&\s*|\bthen\s+|\belse\s+|\bdo\s+)\s*{nom}[ \t]+(?![ \t]*[=:])", code):   # `debug = false` (contenu d'un heredoc) n'est pas un appel
                appelees.add(nom)
    assert appelees <= definies, f"appelées sans être définies : {sorted(appelees - definies)}"


def test_warn_est_defini_avant_sa_premiere_utilisation():
    d = TEXTE.index("warn()")
    assert d < TEXTE.index('warn "')


def test_parted_repond_oui_a_la_confirmation_de_partition_montee():
    assert "---pretend-input-tty" in TEXTE
    assert not re.search(r"parted -s \"\$root_disk\" resizepart", TEXTE), "parted -s échoue sur une partition montée"


def test_une_extension_qui_echoue_n_arrete_pas_le_script():
    """Le premier appel du script à expand_filesystem ne doit pas pouvoir faire échouer le script sous set -e."""
    assert re.search(r"^expand_filesystem\s*\|\|", TEXTE, re.M) or re.search(r"^if ! expand_filesystem", TEXTE, re.M)

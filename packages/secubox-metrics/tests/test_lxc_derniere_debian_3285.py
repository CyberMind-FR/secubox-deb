# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Conteneur LXC en dernière Debian stable (#3285).

Le script de création ne fige plus `bookworm` : la suite est celle de l'hôte
(`suite_debian_hote`, repli trixie), et les pièges de trixie en LXC non
privilégié sont traités (`ImportCredential=` vidé sous systemd >= 257, gpg au
lieu de gnupg qui peut tirer un MTA, PHP sans version en dur).
"""
import re
import subprocess
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
SCRIPTS = [RACINE / "composants/grafana/lib/grafana/install-lxc.sh"]


def _code(chemin):
    """Lignes de code (commentaires de shell ignorés)."""
    return [ligne for ligne in chemin.read_text(encoding="utf-8").splitlines() if not ligne.lstrip().startswith("#")]


def test_aucune_suite_bookworm_en_dur():
    for s in SCRIPTS:
        fautives = [ligne.strip() for ligne in _code(s) if "bookworm" in ligne]
        assert not fautives, f"{s.name} : bookworm en dur {fautives}"


def test_suite_de_l_hote_et_credentials_systemd():
    for s in SCRIPTS:
        texte = s.read_text(encoding="utf-8")
        assert "suite_debian_hote() {" in texte, s
        assert "suite_debian_hote)" in texte, f"{s.name} : la suite par défaut doit venir de suite_debian_hote"
        assert "lxc_sans_credentials() {" in texte, s
        assert re.search(r'^\s+lxc_sans_credentials "\$', texte, re.M), f"{s.name} : drop-in ImportCredential jamais posé"


def test_pas_de_gnupg_ni_de_php_versionne():
    for s in SCRIPTS:
        code = "\n".join(_code(s))
        assert not re.search(r"(?<![A-Za-z_])gnupg(?![A-Za-z_])", code), f"{s.name} : gpg, pas gnupg (#3274)"
        assert not re.search(r"php\d\.\d", code), f"{s.name} : PHP sans version en dur"


def test_suite_lue_dans_os_release(tmp_path):
    for s in SCRIPTS:
        texte = s.read_text(encoding="utf-8")
        fonction = re.search(r"^suite_debian_hote\(\) \{\n.*?^\}\n", texte, re.M | re.S).group(0)
        for contenu, attendu in (("ID=debian\nVERSION_CODENAME=forky\n", "forky"),
                                 ("ID=ubuntu\nVERSION_CODENAME=noble\n", "trixie"),
                                 (None, "trixie")):
            osr = tmp_path / "os-release"
            if contenu is None:
                osr.unlink(missing_ok=True)
            else:
                osr.write_text(contenu)
            sortie = subprocess.run(["bash", "-c", fonction + "suite_debian_hote"], check=True, timeout=10,
                                    capture_output=True, text=True, env={"SECUBOX_OS_RELEASE": str(osr), "PATH": "/usr/bin:/bin"})
            assert sortie.stdout.strip() == attendu, (s.name, contenu)

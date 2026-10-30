# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L5 (R-L5-27) : une box passée « distante » est servie par le pilotage du maître ; relais-maillage ne relaie plus SON
nom admin.<box> (liste d'exclusion root écrite par secubox-pilotage-vhost), et seulement celui-là."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()


def _execute(tmp_path, fichier, nom):
    debut = TEXTE.index("nom_exclu_pilotage() {")
    code = re.search(r"<<'PY'\n(.*?)\nPY\n", TEXTE[debut:], re.S).group(1)
    f = tmp_path / "exclu.py"
    f.write_text(code)
    env = {"PATH": os.environ["PATH"], "SBX_UID_ATTENDU_EXCLUSIONS": str(os.getuid())}
    return subprocess.run([sys.executable, "-I", str(f), str(fichier), nom], capture_output=True, text=True, env=env).returncode


def _fichier(tmp_path, noms, mode=0o644):
    d = tmp_path / "pages"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o755)
    f = d / "exclusions-relais.json"
    f.write_text(json.dumps({"noms": noms}))
    os.chmod(f, mode)
    return f


def test_nom_admin_exclu_seulement(tmp_path):
    f = _fichier(tmp_path, ["admin.gk5.secubox.in", "hall.gk5.secubox.in"])
    assert _execute(tmp_path, f, "admin.gk5.secubox.in") == 0
    assert _execute(tmp_path, f, "hall.gk5.secubox.in") == 1      # jamais les autres noms de la box, même listés
    assert _execute(tmp_path, f, "admin.gk4.secubox.in") == 1
    assert _execute(tmp_path, f, "admin.gk5.secubox.in.evil") == 1


def test_fichier_absent_ou_non_sur_n_exclut_rien(tmp_path):
    assert _execute(tmp_path, tmp_path / "absent.json", "admin.gk5.secubox.in") == 1
    f = _fichier(tmp_path, ["admin.gk5.secubox.in"], mode=0o666)
    assert _execute(tmp_path, f, "admin.gk5.secubox.in") == 1
    lien = tmp_path / "lien.json"
    f2 = _fichier(tmp_path, ["admin.gk5.secubox.in"])
    lien.symlink_to(f2)
    assert _execute(tmp_path, lien, "admin.gk5.secubox.in") == 1


def test_synchronisation_et_relayer_honorent_l_exclusion():
    s = TEXTE[TEXTE.index("cmd_synchroniser() {"):TEXTE.index("cmd_retirer() {")]
    boucle = s[s.index('for nom in $liste; do'):s.index('publies="$publies $nom"')]
    assert 'nom_exclu_pilotage "$nom"' in boucle and "continue" in boucle
    r = TEXTE[TEXTE.index("cmd_relayer() {"):]
    r = r[:r.index("\n}\n")]
    assert 'nom_exclu_pilotage "$nom"' in r and "meurt" in r
    assert "/var/lib/secubox-pilotage-pages/exclusions-relais.json" in TEXTE

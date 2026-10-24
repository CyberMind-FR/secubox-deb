# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3132 — relais du maillage : les services propres à un pair sont publiés (réglage services_des_pairs), et un nom
relayé vers un pair qui ne le publie plus est retiré. Le script exige root : on teste son Python réel (noms_perimes)
et le texte de la synchronisation."""
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-relais-maillage"
TEXTE = SCRIPT.read_text()


def _python_de(fonction):
    debut = TEXTE.index(fonction + "() {")
    return re.search(r"<<'PY'\n(.*?)\nPY\n", TEXTE[debut:], re.S).group(1)


def _perimes(tmp_path, routes, ip, dpair, publies):
    f = tmp_path / "routes.json"
    f.write_text(json.dumps(routes))
    code = tmp_path / "perimes.py"
    code.write_text(_python_de("noms_perimes"))
    r = subprocess.run([sys.executable, "-I", str(code), str(f), ip, dpair, *publies], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.split()


def test_seuls_les_noms_du_pair_qu_il_ne_publie_plus(tmp_path):
    routes = {
        "bbs.gk1.secubox.in": ["10.10.0.8", 9080],          # gk1 ne le publie plus : périmé
        "hall.gk1.secubox.in": ["10.10.0.8", 9080],         # publié : gardé
        "socialrelay.gk1.secubox.in": ["10.10.0.8", 9080],  # retiré du parc : périmé
        "hall.gk3.secubox.in": ["10.10.0.5", 9080],         # autre pair : jamais touché
        "hall.gk2.secubox.in": ["127.0.0.1", 9080],         # le relais lui-même : jamais touché
        "x.autre.fr": ["10.10.0.8", 9080],                  # même IP, autre domaine : jamais touché
    }
    assert _perimes(tmp_path, routes, "10.10.0.8", "gk1.secubox.in", ["hall.gk1.secubox.in"]) == [
        "bbs.gk1.secubox.in", "socialrelay.gk1.secubox.in"]


def test_routes_illisibles_rien_n_est_perime(tmp_path):
    f = tmp_path / "routes.json"
    f.write_text("{pas du json")
    code = tmp_path / "perimes.py"
    code.write_text(_python_de("noms_perimes"))
    r = subprocess.run([sys.executable, "-I", str(code), str(f), "10.10.0.8", "gk1.secubox.in"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == ""


def test_synchronisation_publie_les_services_propres_et_retire_les_perimes():
    s = TEXTE[TEXTE.index("cmd_synchroniser() {"):TEXTE.index("cmd_retirer() {")]
    assert "reglage services_des_pairs" in s
    assert '[ "$mode" = "communs" ]' in s              # l'ancien filtre ne s'applique plus qu'en mode « communs »
    assert "noms_perimes" in s and "RELAIS_EN_LOT=1 cmd_retirer" in s
    assert "generate --allow-shrink" in s


def test_retirer_reduit_vraiment_haproxy():
    r = TEXTE[TEXTE.index("cmd_retirer() {"):]
    r = r[:r.index("\n}\n")]
    assert "haproxyctl generate --allow-shrink" in r
    assert 'RELAIS_EN_LOT' in r

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3946 — importer `api.main` ne crée rien et ne dépend pas de /var/lib/secubox.

CONSTAT : `api/main.py` créait /var/lib/secubox/soc à l'import ; sans ce droit (CI), les 12 fichiers de tests qui
l'importent tombaient en erreur de collecte et SADE n'était joué nulle part. Chaque cas tourne dans un processus
neuf : un import déjà fait par une autre suite ne prouverait rien."""
import json
import os
import subprocess
import sys
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
COMMUN = PAQUET.parents[1] / "common"


def _python(code, dossier):
    env = {**os.environ, "SECUBOX_SOC_DATA": str(dossier), "PYTHONPATH": f"{COMMUN}:{PAQUET}"}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env, check=False)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_l_import_ne_cree_aucun_dossier(tmp_path):
    d = tmp_path / "soc"
    _python("import api.main", d)
    assert not d.exists()


def test_l_import_survit_a_un_dossier_impossible_a_creer(tmp_path):
    barrage = tmp_path / "fichier"
    barrage.write_text("")                      # un fichier à la place du parent : mkdir échoue, même en root
    _python("import api.main", barrage / "soc")


def test_tous_les_fichiers_d_etat_suivent_la_variable(tmp_path):
    d = tmp_path / "soc"
    out = _python("import json, api.main as m; print(json.dumps([str(p) for p in (m.TICKETS_FILE, m.INTEL_FILE,"
                  " m.PEERS_FILE, m.ALERTS_FILE, m.WEBHOOKS_FILE, m.STATS_FILE, m.MITM_DB)]))", d)
    assert {str(Path(p).parent) for p in json.loads(out)} == {str(d)}


def test_le_chemin_de_production_est_inchange():
    env = {k: v for k, v in os.environ.items() if k != "SECUBOX_SOC_DATA"} | {"PYTHONPATH": f"{COMMUN}:{PAQUET}"}
    r = subprocess.run([sys.executable, "-c", "import api.main as m; print(m.DATA_DIR)"], capture_output=True,
                       text=True, timeout=60, env=env, check=True)
    assert r.stdout.strip() == "/var/lib/secubox/soc"


def test_la_premiere_ecriture_cree_le_dossier(tmp_path):
    d = tmp_path / "soc"
    _python("import api.main as m; m._save_json(m.TICKETS_FILE, [{'id': 'a'}]);"
            "assert m._load_json(m.TICKETS_FILE) == [{'id': 'a'}]", d)
    assert (d / "tickets.json").is_file()


def test_une_ecriture_refusee_est_journalisee(tmp_path):
    barrage = tmp_path / "fichier"
    barrage.write_text("")
    env = {**os.environ, "SECUBOX_SOC_DATA": str(barrage / "soc"), "PYTHONPATH": f"{COMMUN}:{PAQUET}"}
    r = subprocess.run([sys.executable, "-c", "import api.main as m; m._save_json(m.TICKETS_FILE, [])"],
                       capture_output=True, text=True, timeout=60, env=env, check=True)
    assert "tickets.json" in r.stderr + r.stdout

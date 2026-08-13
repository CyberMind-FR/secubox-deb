# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Le réchauffeur de cache par minuterie (#1028)."""
import subprocess
import sys
import tomllib
from pathlib import Path

RUNNER = Path(__file__).resolve().parents[1] / "sbin" / "secubox-cache-warm"
CONF = Path(__file__).resolve().parents[1] / "etc" / "secubox" / "cache-warmers.toml"


def test_le_runner_est_du_python_valide():
    import ast
    ast.parse(RUNNER.read_text())


def test_la_configuration_est_du_toml_valide():
    d = tomllib.load(CONF.open("rb"))
    assert set(d) == {"metacatalog", "jitsi"}
    for mod, e in d.items():
        assert e.get("fonction"), f"{mod} sans fonction"


def test_sans_argument_le_runner_refuse():
    r = subprocess.run([sys.executable, str(RUNNER)], capture_output=True, text=True)
    assert r.returncode == 2 and "usage" in r.stderr


def test_un_module_non_declare_echoue_bruyamment(tmp_path, monkeypatch):
    """Une minuterie qui « réussit » sans rien faire est exactement le genre de
    mécanisme qu'on corrige ici : l'absence de déclaration doit se voir."""
    src = RUNNER.read_text().replace(
        'CONF = Path("/etc/secubox/cache-warmers.toml")',
        f'CONF = Path("{tmp_path / "vide.toml"}")')
    faux = tmp_path / "runner.py"
    faux.write_text(src)
    (tmp_path / "vide.toml").write_text("")
    r = subprocess.run([sys.executable, str(faux), "inconnu"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "non déclaré" in r.stderr


def test_seules_les_fonctions_declarees_sont_appelables():
    # Le nom vient du fichier de configuration, jamais d'un argument libre :
    # ce runner tourne en root, et importer un module pour y appeler un nom
    # arbitraire serait un moyen d'exécution détourné.
    src = RUNNER.read_text()
    assert 'entree["fonction"]' in src
    assert "argv[2]" not in src, "la fonction ne doit pas venir de la ligne de commande"

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Le postinst recrée le venv quand la version de Python change (Debian 12 -> 13)."""
from pathlib import Path

POSTINST = Path(__file__).resolve().parents[1] / "debian" / "postinst"


def test_le_venv_est_recree_si_la_version_de_python_change():
    texte = POSTINST.read_text()
    assert "version_info" in texte, "le postinst doit comparer la version de Python du venv au système"
    assert "venv.py" in texte, "l'ancien venv doit être conservé sous un autre nom, pas supprimé"

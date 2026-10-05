# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""L'unité geoipupdate attend le DNS local et se relance si le réseau n'est pas prêt."""
from pathlib import Path

UNITE = Path(__file__).resolve().parents[1] / "systemd" / "secubox-geoipupdate.service"


def test_attend_le_resolveur_local():
    assert "After=" in UNITE.read_text()
    ligne_after = [l for l in UNITE.read_text().splitlines() if l.startswith("After=")][0]
    assert "unbound.service" in ligne_after


def test_se_relance_apres_un_echec_de_resolution():
    texte = UNITE.read_text()
    assert "Restart=on-failure" in texte
    assert "RestartSec=" in texte

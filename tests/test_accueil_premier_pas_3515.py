# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""/ ouvre l'assistant sur une box neuve, seulement si le marqueur « à faire » existe (#3515)."""
from pathlib import Path

R = Path(__file__).resolve().parents[1]
MARQUE = "/var/lib/secubox/.premier-pas-a-faire"


def test_nginx_teste_le_marqueur_positif_jamais_l_absence():
    for f in ("common/nginx/secubox.conf", "packages/secubox-hub/nginx/webui.conf"):
        s = (R / f).read_text(encoding="utf-8")
        assert f"if (-f {MARQUE}) {{ return 302 /premier-pas/; }}" in s
        assert ".premier-pas-fait" not in s


def test_firstboot_ne_pose_pas_le_marqueur_sur_une_box_configuree():
    s = (R / "image/firstboot.sh").read_text(encoding="utf-8")
    assert "! -e /var/lib/secubox/.premier-pas-fait" in s and MARQUE in s

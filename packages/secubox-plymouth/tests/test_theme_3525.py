# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
from pathlib import Path

R = Path(__file__).resolve().parents[1]
T = R / "theme/secubox-dice"


def test_toutes_les_images_et_script_sans_ternaire():
    assert len(list(T.glob("de-*.png"))) == 90 and (T / "barre.png").exists() and (T / "barre-fond.png").exists()
    assert " ? " not in (T / "secubox-dice.script").read_text(encoding="utf-8")


def test_jamais_apres_multi_user():
    for f in (R / "systemd").rglob("*.conf"):
        assert "After=multi-user" not in f.read_text(encoding="utf-8")

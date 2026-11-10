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


def test_positions_recalculees_a_chaque_image_3636():
    """RPi400 HDMI : le framebuffer du firmware puis vc4 changent la taille de l'écran ; un centre calculé
    une seule fois au chargement tombait en bas à droite. Tout positionnement passe par placer(), appelé
    à chaque rafraîchissement."""
    s = (T / "secubox-dice.script").read_text(encoding="utf-8")
    debut = s.index("fun placer()")
    fin = s.index("}", debut)
    corps_placer = s[debut:fin]
    hors_placer = s[:debut] + s[fin:]
    assert "Window.GetWidth()" in corps_placer and "Window.GetHeight()" in corps_placer
    assert "Window.GetWidth()" not in hors_placer and "Window.GetX()" not in hors_placer
    raf = s[s.index("fun rafraichir()"):]
    assert "placer();" in raf[:raf.index("}")]
    # état partagé modifié dans une fonction : toujours par global. (sinon variable locale)
    for var in ("n", "plus_loin", "message_largeur"):
        assert f"global.{var} =" in s, var

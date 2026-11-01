# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3366 — les LED du MOCHAbin sont un affichage permanent : le sleeper ne doit jamais les endormir.

gk2, 2026-11-01 : audit « led-pulse stop idle-sleep » à 06:22 et 07:40, LED éteintes. Décision du propriétaire :
le module LED reste permanent sur les MOCHAbin (sans LED, la garde secubox-led-board les rend inertes)."""
import tomllib
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
POLITIQUE = tomllib.loads((PKG / "policy" / "lifecycle-defaults.toml").read_text())["lifecycle"]
FAMILLE_LED = ("leds", "led-pulse", "led-flux", "led-nft", "led-heartbeat", "led-trigger", "led-health-bumper")


def test_famille_led_toujours_active():
    for module in FAMILLE_LED:
        assert POLITIQUE.get(module) == "always-on", module

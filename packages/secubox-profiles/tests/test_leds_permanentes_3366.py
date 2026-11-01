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


def test_postinst_migre_les_manifestes_led(tmp_path):
    """Un manifeste existant fait autorité (scan n'écrase pas sans --force) : le postinst
    passe les seuls manifestes LED encore on-demand en always-on, sans toucher aux autres."""
    import subprocess
    d = tmp_path / "modules.d"
    d.mkdir()
    for m in ("led-pulse", "leds"):
        (d / f"{m}.toml").write_text(f'id = "{m}"\nlifecycle = "on-demand"\n')
    (d / "jellyfin.toml").write_text('id = "jellyfin"\nlifecycle = "on-demand"\n')
    (d / "led-trigger.toml").write_text('id = "led-trigger"\nlifecycle = "never"\n')
    script = (PKG / "debian" / "postinst").read_text()
    debut = script.index("# --- migration LED always-on (#3366)")
    fin = script.index("# --- fin migration LED", debut)
    bloc = script[debut:fin]
    subprocess.run(["bash", "-c", f'MODULES_D="{d}"\n{bloc}'], check=True)
    assert 'lifecycle = "always-on"' in (d / "led-pulse.toml").read_text()
    assert 'lifecycle = "always-on"' in (d / "leds.toml").read_text()
    assert 'lifecycle = "on-demand"' in (d / "jellyfin.toml").read_text()
    assert 'lifecycle = "never"' in (d / "led-trigger.toml").read_text()

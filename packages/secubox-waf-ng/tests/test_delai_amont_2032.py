# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2032 — sbxwaf ne doit pas couper avant HAProxy.

HAProxy accorde 10 min à la synthèse vocale et 1 h au studio natif de VoiceStudio ; sbxwaf, derrière lui,
coupait à 120 s pour tous les hôtes : « 504 : timeout awaiting response headers » sur /generate (gk3).
HAProxy borne déjà le trafic ordinaire à 30 s, donc le délai amont de sbxwaf n'a pas à être plus court
que le plus long délai accordé en amont de lui."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
RACINE = PAQUET.parents[1]


def _secondes(valeur):
    total = 0
    for nombre, unite in re.findall(r"(\d+)([hms])", valeur):
        total += int(nombre) * {"h": 3600, "m": 60, "s": 1}[unite]
    return total


def test_le_delai_amont_de_sbxwaf_couvre_le_plus_long_delai_haproxy():
    unite = (PAQUET / "systemd" / "secubox-waf-ng.service").read_text()
    delai = _secondes(re.search(r"--upstream-timeout\s+(\S+)", unite).group(1))
    haproxyctl = (RACINE / "packages" / "secubox-haproxy" / "sbin" / "haproxyctl").read_text()
    plus_long = max(_secondes(m) for m in re.findall(r"set-timeout server (\w+) if", haproxyctl))
    assert delai >= plus_long, f"sbxwaf coupe à {delai} s, HAProxy accorde jusqu'à {plus_long} s"

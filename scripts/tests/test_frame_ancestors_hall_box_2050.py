# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Chaque politique `frame-ancestors` d'un service encadré par le Hall nomme AUSSI le Hall de cette box.

Constaté sur gk3 : la route admin de Mood nommait seulement hall.gk2.* ; hall.gk3.secubox.in ne pouvait donc
pas l'encadrer (CSP frame-ancestors, carte « micro » vide). `$sbx_hall_box` = le Hall du nom demandé (#1725)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
VHOSTS = [
    "packages/secubox-waf-ng/composants/waf/nginx/waf-vhost.conf",
    "packages/secubox-waf-ng/nginx/actor.gk2.secubox.in.conf",
    "packages/secubox-metablogizer/nginx/metablogizer.vhost.conf",
    "packages/sbxos-audio-mood/nginx/sbxos-audio-mood.conf",
]


def test_les_vhosts_encadres_nomment_le_hall_de_la_box():
    for f in VHOSTS:
        politiques = re.findall(r"frame-ancestors 'self' https://hall\.gk2\.secubox\.in[^;\"]*", (RACINE / f).read_text())
        assert politiques, f
        for p in politiques:
            assert "$sbx_hall_box" in p or "$sbx_mood_hall" in p, f"{f} : {p}"

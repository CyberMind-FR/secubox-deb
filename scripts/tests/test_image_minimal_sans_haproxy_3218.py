# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3218 — l'image minimal ne préinstalle plus haproxy et ne l'active jamais.

Banc de l'ESPRESSObin gk5 (1 Go, 2026-10-28) : haproxy tournait (2 processus, 41 Mo) sans écouter aucun port. Aucun paquet du
profil ne l'exige ; il venait de `apt-get install -y --no-install-recommends haproxy qrencode` dans build-image.sh."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
BUILD = (RACINE / "image" / "build-image.sh").read_text(encoding="utf-8")
NETREADY = (RACINE / "packages" / "secubox-core" / "systemd" / "secubox-network-ready.service").read_text(encoding="utf-8")


def _branche_minimal():
    m = re.search(r'if \[\[ "\$\{PROFILE_TAG\}" == "minimal" \]\]; then\n(.*?)\n(?:elif|else|fi)', BUILD, re.S)
    assert m, "branche minimal de la préinstallation des services absente"
    return m.group(1)


def test_minimal_preinstalle_qrencode_sans_haproxy():
    branche = _branche_minimal()
    assert "qrencode" in branche
    assert "haproxy" not in branche.replace("no haproxy", "")


def test_la_branche_minimal_precede_les_autres():
    """Une carte ESPRESSObin a SECUBOX_LITE=1 : la branche lite (avec haproxy) ne doit pas l'emporter pour minimal."""
    i_min = BUILD.index('if [[ "${PROFILE_TAG}" == "minimal" ]]; then')
    i_lite = BUILD.index('elif [[ "${SECUBOX_LITE:-0}" != "1" ]]; then')
    assert i_min < i_lite


def test_haproxy_present_dans_minimal_est_desactive_et_detache_de_network_online():
    bloc = BUILD[BUILD.index("MINIMAL : HAPROXY JAMAIS ACTIVÉ"):BUILD.index("LE PROFIL EST-IL VRAIMENT LÀ")]
    assert "systemctl disable haproxy.service" in bloc
    assert "network-online.target.wants/haproxy.service" in bloc


def test_network_ready_ordonne_haproxy_sans_le_tirer():
    """secubox-network-ready mentionne haproxy par `Before=` seulement : un ordre, pas une dépendance ; il ne le démarre pas."""
    assert re.search(r"^Before=.*haproxy\.service", NETREADY, re.M)
    for cle in ("Wants", "Requires", "BindsTo", "Requisite", "Upholds", "PartOf"):
        assert not re.search(rf"^{cle}=.*haproxy", NETREADY, re.M), cle

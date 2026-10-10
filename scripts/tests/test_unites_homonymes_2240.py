# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Deux paquets ne livrent jamais une unité du même nom : l'un écrase l'autre sur disque et le perdant n'a plus d'unité. Constaté : le moteur nDPId
(secubox-ndpid-engine) et l'API ndpid (secubox-dpi) livraient tous deux secubox-ndpid.service ; l'API l'emportait, nDPId ne tournait donc jamais."""
import collections
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[2] / "packages"
# Doublon hérité, hors du périmètre de #2240, à traiter séparément : secubox-core et secubox-led-heartbeat.
HERITE = {"secubox-led-heartbeat.service"}


def unites_sources():
    par = collections.defaultdict(set)
    for f in PACKAGES.rglob("*.service"):
        p = f.relative_to(PACKAGES).parts
        if "debian" in p[1:] and f.parent.name != "debian":
            continue                                   # sorties de construction debian/<paquet>/…
        if set(p) & {"_gocache", "_gopath", "vendor", "node_modules"}:
            continue
        par[f.name].add(p[0])
    return par


def test_aucune_unite_n_est_livree_par_deux_paquets():
    doubles = {n: sorted(v) for n, v in unites_sources().items() if len(v) > 1 and n not in HERITE}
    assert not doubles, f"unités livrées par plusieurs paquets : {doubles}"


def test_le_moteur_nDPId_a_sa_propre_unite_et_l_api_l_attend():
    moteur = PACKAGES / "secubox-ndpid-engine"
    assert (moteur / "systemd" / "secubox-ndpid-engine.service").is_file() and not (moteur / "systemd" / "secubox-ndpid.service").exists()
    assert "secubox-ndpid-engine.service" in (moteur / "debian" / "postinst").read_text()
    api = (PACKAGES / "secubox-dpi" / "composants" / "ndpid" / "debian" / "secubox-ndpid.service").read_text()
    assert "Wants=secubox-ndpid-engine.service" in api and "ndpid.service\n" not in api.replace("secubox-ndpid-engine.service", "")

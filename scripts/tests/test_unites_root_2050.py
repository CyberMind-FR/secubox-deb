# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Garde-fou (#2050, vague 0) : aucun nouveau paquet ne livre une unité en User=root.

La liste ci-dessous ne peut que se réduire ; elle est documentée dans
docs/SECURITE-UNITES-ROOT.md.
"""
import glob
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]

PAQUETS_ROOT_TOLERES = {
    "aggregator", "backup", "certs", "cookies", "health",
    "interceptor", "led-heartbeat", "mail", "metrics", "netboot", "haproxy",
    "nettweak", "profiles", "qos", "routes", "system", "threatmesh", "toolbox",
    "mqtt", "vm",
}


def _paquets_root():
    trouves = set()
    # les unités d'un composant absorbé (#2050) vivent sous composants/<absorbé>/ : le garde-fou les suit
    motifs = ("packages/*/debian/*.service", "packages/*/systemd/*.service",
              "packages/*/composants/*/debian/*.service", "packages/*/composants/*/systemd/*.service")
    for motif in motifs:
        for f in glob.glob(str(RACINE / motif)):
            if re.search(r"/debian/secubox-[a-z0-9-]+/", f):
                continue
            texte = Path(f).read_text(errors="ignore")
            if re.search(r"(?m)^User=root\s*$", texte):
                trouves.add(Path(f).relative_to(RACINE).parts[1].removeprefix("secubox-"))
    return trouves


def test_aucun_nouveau_paquet_en_root():
    nouveaux = _paquets_root() - PAQUETS_ROOT_TOLERES
    assert not nouveaux, (
        f"nouvelles unités User=root interdites : {sorted(nouveaux)} "
        "(utilisateur secubox-<module> + assistant sudo étroit ; voir docs/SECURITE-UNITES-ROOT.md)"
    )


def test_registre_ne_garde_pas_de_paquet_corrige():
    obsoletes = PAQUETS_ROOT_TOLERES - _paquets_root()
    assert not obsoletes, f"retirer de la liste et du registre : {sorted(obsoletes)}"


def test_registre_documente_chaque_paquet():
    doc = (RACINE / "docs/SECURITE-UNITES-ROOT.md").read_text()
    manquants = [p for p in sorted(PAQUETS_ROOT_TOLERES) if f"`{p}`" not in doc]
    assert not manquants, f"absents du registre : {manquants}"

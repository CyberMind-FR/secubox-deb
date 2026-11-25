# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3621, #3946 — « bibliothèque | python3-pip » n'installe RIEN quand pip est déjà là, et il l'est dans toute image.

VM bêta 1 : secubox-users en boucle (« Form data requires python-multipart »), l'alternative étant satisfaite par pip.
secubox-core porte les bibliothèques communes sans ce repli : c'est lui qui les garantit aux paquets qui le gardent.
"""
import importlib.util
from pathlib import Path

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
COMMUNES = {"python3-fastapi", "python3-uvicorn", "python3-httpx", "python3-python-multipart", "python3-multipart"}

# Reste à traiter, hors de ce que secubox-core garantit : la liste ne fait que décroître.
TOLERES = {
    ("secubox-console", "python3-httpx"),         # secubox-core n'y est que Recommends
    ("secubox-surf", "python3-uvicorn"),          # sans secubox-core
    ("secubox-metrics", "python3-maxminddb"),
    ("secubox-metrics", "python3-geoip2"),
    ("secubox-toolbox", "python3-fpdf2"),
    ("secubox-webos", "python3-pydantic"),        # tiré par python3-fastapi
}


def _strophes():
    spec = importlib.util.spec_from_file_location("gen_meta_3946", PAQUETS / "secubox-meta" / "gen-meta.py")
    g = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(g)
    return {s["Package"]: s for f in sorted(PAQUETS.glob("*/debian/control")) for s in g.strophes(str(f))}


def _groupes(strophe):
    return [[a.split()[0] for a in g.split("|") if a.strip()]
            for g in (strophe.get("Depends", "") + "," + strophe.get("Pre-Depends", "")).split(",") if g.strip()]


@pytest.fixture(scope="module")
def paquets():
    return _strophes()


def test_secubox_core_exige_les_bibliotheques_sans_repli_pip(paquets):
    groupes = _groupes(paquets["secubox-core"])
    assert not [g for g in groupes if "python3-pip" in g]
    for lib in ("python3-fastapi", "python3-uvicorn", "python3-httpx"):
        assert [lib] in groupes, lib
    assert ["python3-python-multipart", "python3-multipart"] in groupes      # Debian 13, puis Debian 12


def test_tout_repli_pip_restant_est_garanti_par_secubox_core(paquets):
    def atteint(nom, vus):
        for g in _groupes(paquets[nom]):
            if len(g) == 1 and g[0] in paquets and g[0] not in vus:
                vus.add(g[0])
                atteint(g[0], vus)
        return vus

    fautifs = set()
    for nom, s in paquets.items():
        for g in _groupes(s):
            if "python3-pip" in g and len(g) > 1 and not (g[0] in COMMUNES and "secubox-core" in atteint(nom, set())):
                fautifs.add((nom, g[0]))
    assert fautifs - TOLERES == set(), f"« | python3-pip » sans garantie : {sorted(fautifs - TOLERES)}"
    assert TOLERES - fautifs == set(), f"tolérances périmées : {sorted(TOLERES - fautifs)}"

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Compatibilité Debian 13 (ref #1294) : les pièges de NOMS de paquets, trouvés en installant dans un chroot Trixie.

Ces deux-là ne se voient pas à la construction (rien n'échoue) : un paquet « installable » sur Debian 12 devient, sur Debian 13,
soit NON installable (nom disparu), soit installable avec la MAUVAISE bibliothèque (nom réaffecté)."""
import re
from pathlib import Path

PACKAGES = Path(__file__).resolve().parents[1] / "packages"


def depends(control: Path) -> str:
    return control.read_text()


def test_python3_multipart_n_est_jamais_seul_sous_debian_13():
    """python3-multipart = python-multipart (Kludex) sous Debian 12, mais multipart 1.2 (autre bibliothèque) sous Debian 13 : la bonne
    s'y nomme python3-python-multipart. Une dépendance au seul ancien nom installe la mauvaise sous Debian 13."""
    fautifs = []
    for c in sorted(PACKAGES.glob("*/debian/control")):
        for ligne in depends(c).splitlines():
            if ligne.lstrip().startswith("#"):
                continue
            for alt in re.findall(r"(?:^|[\s,])((?:[a-z0-9.+-]+(?:\s*\|\s*)?)+)", ligne):
                noms = [n.strip() for n in alt.split("|")]
                if "python3-multipart" in noms and "python3-python-multipart" not in noms:
                    fautifs.append(f"{c.parent.parent.name}: {ligne.strip()}")
    assert not fautifs, "python3-multipart sans python3-python-multipart :\n" + "\n".join(fautifs)


def test_le_coeur_exige_la_bonne_bibliotheque_de_formulaires():
    core = (PACKAGES / "secubox-core" / "debian" / "control").read_text()
    assert "python3-python-multipart | python3-multipart" in core


def test_dnsutils_n_est_jamais_seul_sous_debian_13():
    """`dnsutils` a disparu de Debian 13 : bind9-dnsutils (qui existe aussi sous Debian 12) doit être proposé en premier."""
    for c in sorted(PACKAGES.glob("*/debian/control")):
        for ligne in depends(c).splitlines():
            if ligne.lstrip().startswith("#"):
                continue
            if re.search(r"(?:^|[\s,|])dnsutils(?:[\s,|(]|$)", ligne) and "bind9-dnsutils" not in ligne:
                raise AssertionError(f"{c.parent.parent.name}: {ligne.strip()}")

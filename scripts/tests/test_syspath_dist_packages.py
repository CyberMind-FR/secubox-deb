# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Aucun module ne place les paquets Debian EN TÊTE du chemin Python (#1796).

`sys.path.insert(0, "/usr/lib/python3/dist-packages")` met le websockets 10.4
de Debian devant celui de /usr/local qu'attend uvicorn ≥ 0.54 : le service
meurt au démarrage (« cannot import name ServerProtocol ») et boucle — vécu
sur gk2 et gk3 (secubox-users, -zkp, -repo, -p2p, -profiles…). Ajouter en
queue s'il manque, jamais en tête.
"""
import pathlib
import re

RACINE = pathlib.Path(__file__).resolve().parents[2]
MOTIF = re.compile(r"sys\.path\.insert\(\s*0\s*,\s*['\"]/usr/lib/python3/dist-packages/?['\"]\s*\)")


def _sources():
    for base in ("packages", "common"):
        for p in (RACINE / base).rglob("*.py"):
            parts = p.relative_to(RACINE).parts
            # Arbres de construction debian/<paquet>/ : copies, pas des sources.
            if "debian" in parts or ".gopath" in parts or "node_modules" in parts:
                continue
            yield p


def test_aucune_insertion_en_tete_des_paquets_debian():
    fautifs = []
    for p in _sources():
        try:
            texte = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, ligne in enumerate(texte.splitlines(), 1):
            if MOTIF.search(ligne) and not ligne.lstrip().startswith("#"):
                fautifs.append(f"{p.relative_to(RACINE)}:{n}")
    assert not fautifs, ("sys.path.insert(0, dist-packages) masque /usr/local "
                         "(uvicorn en boucle, #1796) :\n  " + "\n  ".join(fautifs))


def test_le_motif_attrape_bien_la_forme_fautive():
    assert MOTIF.search("sys.path.insert(0, '/usr/lib/python3/dist-packages')")
    assert MOTIF.search('sys.path.insert(0,"/usr/lib/python3/dist-packages/")')
    assert not MOTIF.search('sys.path.append("/usr/lib/python3/dist-packages")')

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import re
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _generer(tmp_path):
    r = subprocess.run(["bash", str(CTL), "generer-chaine"],
                       env={"PATH": "/usr/bin:/bin", "SECUBOX_PR_NFT_OUT": str(tmp_path / "chaine.nft")},
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return (tmp_path / "chaine.nft").read_text()


def test_politique_default_drop(tmp_path):
    txt = _generer(tmp_path)
    assert re.search(r"chain forward \{[^}]*policy drop;", txt, re.S)


def test_lan_allowed_et_zones_connues_acceptees_avant_le_drop(tmp_path):
    txt = _generer(tmp_path)
    assert "@lan_allowed" in txt and "accept" in txt
    assert "@guest_zone" in txt and "@iot_zone" in txt
    # blocked/quarantine restent un drop explicite, avant toute regle d'acceptation
    assert txt.index("@blocked") < txt.index("accept")


def test_nftables_valide_la_syntaxe(tmp_path):
    # Ruling (ref #2940, Tache 2) : le fichier de base synthetique du brief mettait
    # plusieurs `set { ... }` sur une seule ligne sans separateur -> erreur de syntaxe
    # nft elle-meme (pas un defaut de notre chaine). Corrige en un bloc par ligne.
    if not __import__("shutil").which("nft"):
        pytest.skip("nft absent")
    txt = _generer(tmp_path)
    base = tmp_path / "base.nft"
    base.write_text(
        "table inet secubox_nac {\n"
        "\tset lan_allowed { type ether_addr; }\n"
        "\tset guest_zone { type ether_addr; }\n"
        "\tset iot_zone { type ether_addr; }\n"
        "\tset quarantine_zone { type ether_addr; }\n"
        "\tset blocked { type ether_addr; }\n"
        "}\n" + txt
    )
    r = subprocess.run(["nft", "-c", "-f", str(base)], capture_output=True, text=True)
    if r.returncode != 0 and "cache initialization failed" in r.stderr:
        pytest.skip("nft -c sans acces netlink dans cet environnement (sandbox sans CAP_NET_ADMIN)")
    assert r.returncode == 0, r.stderr

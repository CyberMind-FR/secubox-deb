# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — Samba sur le LAN du mode routeur (br-lan), de confiance comme le réseau de la Freebox (décision du 2026-10-26).
Constaté sur gk2 (2026-10-27) : ksmbd n'écoutait que sur eth2 et la table secubox_smb rejetait le 445 venu de br-lan ;
les partages restaient joignables depuis la Freebox seulement. Les ports isolés (lanN, #3201) restent refusés."""
import re
import subprocess
from pathlib import Path

ICI = Path(__file__).resolve().parents[1] / "composants" / "smb"
NFT = (ICI / "nft" / "zz-secubox-smb.nft").read_text(encoding="utf-8")
CONF = (ICI / "etc" / "ksmbd.conf").read_text(encoding="utf-8")
POSTINST = (ICI / "debian" / "postinst").read_text(encoding="utf-8")


def test_445_accepte_depuis_br_lan_avant_le_refus():
    ok = 'iifname "br-lan" tcp dport 445 accept'
    assert ok in NFT
    assert NFT.index(ok) < NFT.index("tcp dport 445 reject")


def test_jamais_un_port_isole_ni_le_wan_entier():
    for ligne in NFT.splitlines():
        if "dport 445 accept" in ligne:
            assert re.search(r'iifname "(eth2|br-lan)"', ligne), ligne
            assert not re.search(r'iifname "lan[0-3]"', ligne), ligne


def test_rechargement_idempotent():
    """Le postinst recharge ce fichier à chaque mise à jour : sans création-suppression, les règles s'empilaient."""
    lignes = [x.strip() for x in NFT.splitlines() if x.strip() and not x.strip().startswith("#")]
    assert lignes[0] == "table inet secubox_smb"
    assert lignes[1] == "delete table inet secubox_smb"
    assert lignes[2] == "table inet secubox_smb {"


def test_ksmbd_ecoute_aussi_br_lan():
    assert re.search(r"^\s*interfaces\s*=\s*eth2 br-lan\s*$", CONF, re.M)
    assert re.search(r"^\s*bind interfaces only\s*=\s*yes\s*$", CONF, re.M)


def _migrer(tmp_path, contenu: str) -> str:
    """Exécute la ligne de migration du postinst (celle qui vise ksmbd.conf) sur une copie."""
    ligne = next(x for x in POSTINST.splitlines() if "interfaces" in x and "sed" in x)
    f = tmp_path / "ksmbd.conf"
    f.write_text(contenu, encoding="utf-8")
    subprocess.run(["bash", "-c", ligne.replace("/etc/ksmbd/ksmbd.conf", str(f))], check=True, timeout=10)
    return f.read_text(encoding="utf-8")


def test_migration_de_l_ancien_defaut(tmp_path):
    assert "\tinterfaces = eth2 br-lan\n" in _migrer(tmp_path, "[global]\n\tinterfaces = eth2\n[data]\n\tpath = /data\n")


def test_migration_idempotente_et_respecte_un_choix(tmp_path):
    deja = "[global]\n\tinterfaces = eth2 br-lan\n"
    assert _migrer(tmp_path, deja) == deja
    choix = "[global]\n\tinterfaces = enp0s31f6\n"
    assert _migrer(tmp_path, choix) == choix

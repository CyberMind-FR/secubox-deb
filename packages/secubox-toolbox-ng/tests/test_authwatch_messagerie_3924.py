# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3924 : leurres de messagerie — éteints par défaut, retirés à tout arrêt, ports accordés avec secubox-hardening."""
import re
from pathlib import Path

PAQUET = Path(__file__).resolve().parents[1]
UNITE = (PAQUET / "debian" / "secubox-authwatch.service").read_text(encoding="utf-8")
GO = (PAQUET / "cmd" / "sbx-authwatch" / "messagerie.go").read_text(encoding="utf-8")
DROPIN = PAQUET.parent / "secubox-hardening" / "nft" / "secubox-leurres-mail.nft"


def test_eteints_par_defaut_et_reglables_sans_dropin():
    lignes = [ln for ln in UNITE.splitlines() if not ln.startswith("#")]
    commande = "\n".join(lignes).split("ExecStart=", 1)[1].split("\nEnvironment=", 1)[0]
    assert commande.rstrip().endswith("--mail-conteneur=${SBX_MAIL_CONTENEUR}")
    assert "Environment=SBX_MAIL_CONTENEUR=" in lignes                      # vide = éteints
    assert "EnvironmentFile=-/etc/secubox/authwatch/authwatch.env" in lignes
    assert lignes.index("Environment=SBX_MAIL_CONTENEUR=") < lignes.index("EnvironmentFile=-/etc/secubox/authwatch/authwatch.env")


def test_redirection_retiree_a_tout_arret():
    stop = [ln for ln in UNITE.splitlines() if ln.startswith("ExecStopPost=")]
    assert stop == ['ExecStopPost=-/usr/sbin/nft "add table ip secubox_leurres_mail; delete table ip secubox_leurres_mail"']


def test_aucune_capacite_de_plus():
    assert "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n" in UNITE
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH\n" in UNITE


def test_ports_accordes_avec_hardening():
    couples = {(int(a), int(b)) for a, b in re.findall(r"Port: (\d+), Local: (\d+)", GO)}
    assert {p for p, _ in couples} == {25, 465, 587, 993, 995}
    regle = next(ln for ln in DROPIN.read_text(encoding="utf-8").splitlines() if "tcp dport" in ln)
    locaux, publics = (set(map(int, m.split(","))) for m in re.findall(r"\{([\d, ]+)\}", regle))
    assert locaux == {b for _, b in couples} and publics == {p for p, _ in couples}
    assert "ct status dnat" in regle

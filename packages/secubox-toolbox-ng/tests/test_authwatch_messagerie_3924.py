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


MAIN = (PAQUET / "cmd" / "sbx-authwatch" / "main.go").read_text(encoding="utf-8")


def test_eteints_par_defaut_et_jamais_d_environmentfile():
    """R36 : /etc/secubox appartient au compte secubox ; un EnvironmentFile y injecterait LD_PRELOAD dans une unité root."""
    actives = "\n".join(ln for ln in UNITE.splitlines() if not ln.startswith("#"))
    assert "EnvironmentFile" not in actives and "Environment=" not in actives
    assert "--mail-conteneur" not in actives and "SBX_MAIL" not in actives
    assert 'flag.String("mail-conteneur", ""' in MAIN
    assert 'flag.String("reglages", "/etc/default/secubox-authwatch"' in MAIN and "lireReglages(*reglagesF, 0)" in MAIN


def test_pas_de_vidage_memoire_ni_fichier_ouvert():
    assert "\nLimitCORE=0\n" in UNITE and "\nUMask=0027\n" in UNITE


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

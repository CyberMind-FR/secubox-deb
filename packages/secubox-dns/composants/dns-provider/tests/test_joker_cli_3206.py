# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3206 — secubox-dns-joker : verbe étroit, sortie JSON, codes, audit sans clé d'API."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path

from test_joker_3206 import GANDI, Faux

CLI = Path(__file__).resolve().parents[1] / "sbin" / "secubox-dns-joker"


def _cli():
    chargeur = importlib.machinery.SourceFileLoader("secubox_dns_joker", str(CLI))
    spec = importlib.util.spec_from_loader("secubox_dns_joker", chargeur)
    mod = importlib.util.module_from_spec(spec)
    chargeur.exec_module(mod)
    return mod


def _lancer(capsys, argv, faux):
    audits = []

    def charger():
        # le faux refuse par RuntimeError, comme le vrai par HTTPException : c'est l'erreur fournisseur déclarée
        return ([("df97", faux)], lambda nom, ip: (nom, ip), lambda action, d: audits.append((action, d)),
                (RuntimeError,))

    code = _cli().main(argv, charger=charger)
    return code, json.loads(capsys.readouterr().out), audits


def test_usage(capsys):
    for argv in ([], ["assurer", "gk4.secubox.in"], ["creer", "gk4.secubox.in", "82.67.100.75"]):
        code, sortie, audits = _lancer(capsys, argv, Faux(["secubox.in"]))
        assert code == 2 and "usage" in sortie["erreur"] and audits == []


def test_cree_et_audite(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "82.67.100.75"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 0 and sortie["etat"] == "cree" and sortie["nom"] == "*.gk4"
    assert audits[0][0] == "record_created" and audits[0][1]["name"] == "*.gk4"


def test_inchange_sans_audit(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk3.secubox.in", "82.67.100.75"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 0 and sortie["etat"] == "inchange" and audits == []


def test_refus_code_3_et_audite(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "192.168.1.200"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}))
    assert code == 3 and "publique" in sortie["erreur"]
    assert audits[0][0] == "joker_refuse"


def test_echec_fournisseur_code_1(capsys):
    code, sortie, audits = _lancer(capsys, ["assurer", "gk4.secubox.in", "82.67.100.75"],
                                   Faux(["secubox.in"], {"secubox.in": list(GANDI)}, refuse=True))
    assert code == 1 and "409" in sortie["erreur"] and audits[0][0] == "joker_echec"

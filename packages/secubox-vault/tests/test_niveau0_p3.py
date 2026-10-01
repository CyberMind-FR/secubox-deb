# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Niveau 0 du Coffre (P3, #1367) : systemd-creds, bascule en deux temps.

systemd-creds exige root et la clé d'hôte : une doublure le remplace (base64),
on teste la LOGIQUE — déclaration à l'unité, index, et surtout les gardes qui
empêchent de détruire un clair tant que l'unité ne porte pas la crédence.
"""
import base64
import subprocess

import pytest

from coffre import niveau0 as n


@pytest.fixture
def systeme(monkeypatch, tmp_path):
    monkeypatch.setattr(n, "CREDSTORE", tmp_path / "credstore")
    monkeypatch.setattr(n, "SYSTEMD_ETC", tmp_path / "systemd")
    monkeypatch.setattr(n, "CREDENTIALS_RUN", tmp_path / "run-credentials")
    etat = {"porte": False, "corrompre": False}

    def faux_run(args, input=None, capture_output=True, text=False, **k):
        if args[:2] == ["systemd-creds", "encrypt"]:
            dest = args[-1]
            donnees = base64.b64encode(input)
            if etat["corrompre"]:
                donnees = base64.b64encode(b"autre chose")
            open(dest, "wb").write(donnees)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if args[:2] == ["systemd-creds", "decrypt"]:
            return subprocess.CompletedProcess(args, 0, base64.b64decode(open(args[3], "rb").read()), b"")
        if args[:2] == ["systemctl", "show"]:
            unite = args[-1]
            # systemd 252 : la crédence s'affiche « [unprintable] » ; seul le
            # répertoire de l'unité vivante prouve qu'elle l'a reçue.
            d = tmp_path / "run-credentials" / unite
            if etat["porte"]:
                d.mkdir(parents=True, exist_ok=True)
                (d / "radio-sysop").write_text("x")
            return subprocess.CompletedProcess(args, 0, "LoadCredentialEncrypted=[unprintable]\nActiveState=active\n", "")
        return subprocess.CompletedProcess(args, 0, "" if text else b"", "" if text else b"")

    monkeypatch.setattr(n.subprocess, "run", faux_run)
    clair = tmp_path / "secrets" / "radio-sysop"
    clair.parent.mkdir()
    clair.write_text("sysop-tres-secret\n")
    return etat, clair


def test_migrer_declare_et_garde_le_clair(systeme):
    etat, clair = systeme
    e = n.migrer("radio-sysop", str(clair), "secubox-radio.service")
    assert e == {"chemin": str(clair), "unites": ["secubox-radio.service"]}
    d = n.dropin("radio-sysop", "secubox-radio.service").read_text()
    assert "LoadCredentialEncrypted=radio-sysop:" in d and "radio-sysop.cred" in d
    assert clair.exists() and n.dechiffrer("radio-sysop") == b"sysop-tres-secret\n"
    assert oct(n.chemin_cred("radio-sysop").stat().st_mode & 0o777) == "0o600"


def test_credence_infidele_rien_ne_change(systeme):
    etat, clair = systeme
    etat["corrompre"] = True
    with pytest.raises(n.ErreurNiveau0):
        n.migrer("radio-sysop", str(clair), "secubox-radio.service")
    assert not n.chemin_cred("radio-sysop").exists()
    assert not n.dropin("radio-sysop", "secubox-radio.service").exists()


def test_retirer_clair_seulement_quand_l_unite_porte_la_credence(systeme):
    etat, clair = systeme
    n.migrer("radio-sysop", str(clair), "secubox-radio.service")
    with pytest.raises(n.ErreurNiveau0, match="redémarrer"):
        n.retirer_clair("radio-sysop")
    assert clair.exists()
    etat["porte"] = True
    clair.write_text("valeur changée entre-temps\n")
    with pytest.raises(n.ErreurNiveau0, match="diffère"):
        n.retirer_clair("radio-sysop")
    clair.write_text("sysop-tres-secret\n")
    assert n.retirer_clair("radio-sysop") == str(clair) and not clair.exists()
    assert n.etat()[0]["clair_present"] is False


@pytest.mark.parametrize("nom,unite", [("../x", "a.service"), ("ok", "pas-une-unite"), ("ok", "a.service;rm")])
def test_noms_valides_seulement(systeme, nom, unite):
    _, clair = systeme
    with pytest.raises(n.ErreurNiveau0):
        n.migrer(nom, str(clair), unite)

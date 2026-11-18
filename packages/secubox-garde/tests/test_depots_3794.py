# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — aide root secubox-garde-depots : revalidation, double tampon de garde.toml, clé SMS, liens refusés."""
import importlib.machinery
import importlib.util
import os
import pwd
import tomllib
from pathlib import Path

import pytest

CHEMIN = str(Path(__file__).resolve().parents[1] / "lib" / "secubox-garde-depots")


@pytest.fixture
def aide(tmp_path, monkeypatch):
    chargeur = importlib.machinery.SourceFileLoader("garde_depots", CHEMIN)
    spec = importlib.util.spec_from_loader("garde_depots", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    (tmp_path / "depot").mkdir()
    (tmp_path / "secrets").mkdir()
    (tmp_path / "garde.toml").write_text('automatique = true\nquarantaines_max = 2\n')
    moi = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(m, "DEPOT", str(tmp_path / "depot"))
    monkeypatch.setattr(m, "TOML", str(tmp_path / "garde.toml"))
    monkeypatch.setattr(m, "CLE", str(tmp_path / "secrets" / "garde-sms"))
    monkeypatch.setattr(m, "AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(m, "COMPTE", moi.pw_name)
    return m, tmp_path


def test_reglages_appliques_en_double_tampon(aide):
    m, t = aide
    (t / "depot" / "reglages.json").write_text('{"automatique": false, "courriel": "a\\"b@exemple.fr"}')
    m.main()
    assert not (t / "depot" / "reglages.json").exists()
    assert tomllib.loads((t / "garde.toml").read_text()) == {"automatique": True, "quarantaines_max": 2}   # refusé
    (t / "depot" / "reglages.json").write_text('{"automatique": false, "courriel": "b@exemple.fr", "sms_utilisateur": "123"}')
    m.main()
    assert tomllib.loads((t / "garde.toml").read_text()) == {"automatique": False, "quarantaines_max": 2,
                                                            "courriel": "b@exemple.fr", "sms_utilisateur": "123"}
    assert tomllib.loads((t / "garde.toml.prec").read_text())["automatique"] is True


def test_cle_posee_0600_puis_retiree_et_jamais_journalisee(aide):
    m, t = aide
    (t / "depot" / "cle-sms").write_text("AbC123")
    m.main()
    cle = t / "secrets" / "garde-sms"
    assert cle.read_text() == "AbC123\n" and oct(cle.stat().st_mode & 0o777) == "0o600"
    assert "AbC123" not in (t / "audit.log").read_text()
    (t / "depot" / "cle-sms").write_text("")
    m.main()
    assert not cle.exists()


def test_lien_refuse(aide):
    m, t = aide
    (t / "cible").write_text("XyZ")
    os.symlink(t / "cible", t / "depot" / "cle-sms")
    m.main()
    assert not (t / "secrets" / "garde-sms").exists() and not (t / "depot" / "cle-sms").exists()

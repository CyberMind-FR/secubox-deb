# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3077 — six modules à unité root montés dans l'agrégateur (`secubox`) : leurs actions échouaient sans le dire.
Preuves gk2 : `sudo -u secubox mailctl status` → « Not installed » (le conteneur tourne) ; `ping` → « Operation not
permitted » ; systemctl refusé par polkit ; /etc/letsencrypt, /etc/secubox/cookies.json, /var/lib/secubox/backups non
inscriptibles. ksm et vm restent montés : leurs écritures passent déjà par un ctl root et un sudoers exact."""
import importlib
from pathlib import Path

ag = importlib.import_module("aggregator.main")
MIGRATE = Path(__file__).resolve().parents[1] / "sbin" / "secubox-aggregator-migrate"
SIX = ("admin", "cloner", "netdiag", "certs", "cookies", "mail")


def test_les_six_modules_ne_sont_plus_montes(tmp_path, monkeypatch):
    conf = tmp_path / "aggregator.toml"
    conf.write_text('modules = ["hub", "admin", "cloner", "netdiag", "certs", "cookies", "mail", "ksm", "vm"]\n')
    monkeypatch.setattr(ag, "CONFIG_FILE", conf)
    assert ag._load_config()["modules"] == ["hub", "ksm", "vm"]


def test_ksm_et_vm_restent_montes():
    assert not {"ksm", "vm"} & ag.DEDICATED_MODULES


def test_le_script_de_migration_les_exclut_aussi():
    ligne = [x for x in MIGRATE.read_text(encoding="utf-8").splitlines() if x.startswith("readonly AGG_EXCLUDE=")][0]
    mots = ligne.split("=", 1)[1].strip('"').split()
    assert set(SIX) <= set(mots)

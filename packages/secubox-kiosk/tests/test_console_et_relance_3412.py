# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Kiosque sur écran public (ref #3412) : jamais d'autologin root, migration de l'ancien, relance après mise à jour."""
import subprocess
from pathlib import Path

import pytest

PAQUET = Path(__file__).resolve().parents[1]
SETUP = PAQUET / "sbin" / "secubox-kiosk-setup"
RETIRE = PAQUET / "sbin" / "secubox-kiosk-retire-autologin"
RELANCE = PAQUET / "sbin" / "secubox-kiosk-relance"

ANCIEN = "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %I $TERM\nType=idle\n"


def test_setup_n_ecrit_plus_d_autologin_root():
    t = SETUP.read_text()
    assert "--autologin" not in t
    assert "autologin.conf <<" not in t
    assert "setup_console_secours_tty2" in t and "secubox-kiosk-retire-autologin" in t


def test_unite_generee_ne_se_bat_plus_avec_tty1():
    t = SETUP.read_text()
    assert "Conflicts=getty@tty1" not in t and "Conflicts=getty@tty7.service" in t


def _retire(tmp_path, kiosque=False):
    sent = tmp_path / "kiosk-enabled"
    if kiosque:
        sent.touch()
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_KIOSK_SYSTEMD_ETC": str(tmp_path / "sysd"), "SECUBOX_KIOSK_SENTINELLE": str(sent)}
    return subprocess.run(["sh", str(RETIRE)], env=env, capture_output=True, text=True).returncode


def _pose(tmp_path, tty, nom, contenu):
    d = tmp_path / "sysd" / f"getty@{tty}.service.d"
    d.mkdir(parents=True, exist_ok=True)
    (d / nom).write_text(contenu)
    return d / nom


@pytest.mark.parametrize("contenu", [ANCIEN, ANCIEN.replace("Type=idle\n", ""), "# commentaire\n" + ANCIEN.replace("\n", "  \n")])
def test_migration_retire_le_notre(tmp_path, contenu):
    f = _pose(tmp_path, "tty2", "autologin.conf", contenu)
    assert _retire(tmp_path) == 10
    assert not f.exists() and not f.parent.exists()


def test_migration_laisse_un_reglage_d_operateur(tmp_path):
    f = _pose(tmp_path, "tty2", "autologin.conf", ANCIEN + "Environment=FOO=1\n")
    assert _retire(tmp_path) == 0 and f.exists()


def test_migration_rejouable_sans_rien(tmp_path):
    assert _retire(tmp_path) == 0


def test_tty1_de_l_image_retire_seulement_en_kiosque(tmp_path):
    f = _pose(tmp_path, "tty1", "override.conf", ANCIEN)
    assert _retire(tmp_path, kiosque=False) == 0 and f.exists()
    assert _retire(tmp_path, kiosque=True) == 10 and not f.exists()


def _relance(tmp_path, sentinelle=True, enabled=True, etat="inactive"):
    stubs = tmp_path / "bin"
    stubs.mkdir()
    log = tmp_path / "appels"
    (stubs / "systemctl").write_text(
        f"#!/bin/sh\necho \"$*\" >> {log}\n"
        f"case \"$1\" in is-enabled) [ {int(enabled)} = 1 ];; is-active) echo {etat};; esac\n")
    (stubs / "systemctl").chmod(0o755)
    sent = tmp_path / "s"
    if sentinelle:
        sent.touch()
    run = tmp_path / "run"
    run.mkdir()
    r = subprocess.run(["sh", str(RELANCE)], capture_output=True, text=True,
                       env={"PATH": f"{stubs}:/usr/bin:/bin", "SECUBOX_KIOSK_SENTINELLE": str(sent), "SECUBOX_KIOSK_SYSTEMD_RUN": str(run)})
    assert r.returncode == 0
    return log.read_text() if log.exists() else ""


def test_relance_un_kiosque_active_arrete(tmp_path):
    assert "--no-block start secubox-kiosk.service" in _relance(tmp_path)


@pytest.mark.parametrize("args", [dict(sentinelle=False), dict(enabled=False), dict(etat="active"), dict(etat="activating")])
def test_relance_ne_touche_a_rien_sinon(tmp_path, args):
    assert "start" not in _relance(tmp_path, **args)


def test_paquet_livre_relance_et_migration():
    rules = (PAQUET / "debian" / "rules").read_text()
    for f in ("secubox-kiosk-retire-autologin", "secubox-kiosk-relance", "etc/apt/apt.conf.d/80secubox-kiosk-relance"):
        assert f in rules
    hook = (PAQUET / "apt" / "80secubox-kiosk-relance").read_text()
    assert "DPkg::Post-Invoke" in hook and "|| true" in hook
    post = (PAQUET / "debian" / "postinst").read_text()
    assert "secubox-kiosk-retire-autologin" in post and "secubox-kiosk-relance" in post
    for s in (RETIRE, RELANCE, PAQUET / "debian" / "postinst"):
        assert subprocess.run(["sh", "-n", str(s)]).returncode == 0


def test_premier_pas_relance_le_kiosque_active():
    post = (PAQUET.parent / "secubox-premier-pas" / "debian" / "postinst").read_text()
    assert "/var/lib/secubox/.kiosk-enabled" in post and "--no-block start secubox-kiosk.service" in post

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2615 — trois echecs vus sur /system/ : liste des mises a jour illisible, demarrage de service refuse, kiosque sans droits.

L'API tourne en User=secubox avec NoNewPrivileges=true : systemctl direct et le script kiosque (root) ne pouvaient pas marcher."""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
SYSTEM = PAQUETS / "secubox-system"
KIOSK = PAQUETS / "secubox-kiosk"
sys.path.insert(0, str(PAQUETS.parent / "common"))


def charge_api():
    spec = importlib.util.spec_from_file_location("api_systeme_2615", SYSTEM / "api" / "main.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class Res:
    def __init__(self, out="", rc=0, err=""):
        self.stdout, self.stderr, self.returncode = out, err, rc


# ── 3 : « Inst, Inst, Inst » ─────────────────────────────────────────────
def test_la_liste_des_mises_a_jour_donne_les_noms_de_paquets(monkeypatch):
    api = charge_api()
    sortie = ("Reading package lists...\n"
              "Inst secubox-hub [1.10.2-1~trixie1] (1.11.0-1~trixie1 apt.secubox.in:trixie [all])\n"
              "Inst libssl3t64 [3.5.1-1] (3.5.2-1 Debian:13.7/stable [amd64])\n"
              "Conf secubox-hub (1.11.0-1~trixie1 apt.secubox.in:trixie [all])\n")
    monkeypatch.setattr(api.subprocess, "run", lambda *a, **k: Res(sortie))
    r = api.check_updates(user={"sub": "admin"})
    assert r["packages"] == ["secubox-hub", "libssl3t64"] and r["count"] == 2


# ── 1 : demarrer un service ──────────────────────────────────────────────
def test_la_regle_polkit_est_livree_et_bornee():
    regle = SYSTEM / "polkit" / "50-secubox-system.rules"
    s = regle.read_text()
    assert "org.freedesktop.systemd1.manage-units" in s
    # bornee a l'unite de l'API (le compte secubox est PARTAGE par tous les modules : une regle par utilisateur
    # donnerait a n'importe quel module le droit d'arreter le WAF) et aux unites secubox-*.service
    assert "secubox-system.service" in s and "system_unit" in s
    assert re.search(r"secubox-", s) and "polkit.Result.YES" in s and "NOT_HANDLED" in s
    assert "polkit.Result.YES" not in s.split("function")[0]            # jamais de YES inconditionnel
    install = (SYSTEM / "debian" / "rules").read_text()
    assert "polkit-1/rules.d/50-secubox-system.rules" in install
    assert "polkitd" in (SYSTEM / "debian" / "control").read_text()


# ── 2 : kiosque ──────────────────────────────────────────────────────────
def test_l_unite_root_du_kiosque_n_accepte_que_trois_instances():
    u = (KIOSK / "systemd" / "secubox-kiosk-setup@.service").read_text()
    assert "Type=oneshot" in u and "enable-x11" in u and "enable-wayland" in u and "disable)" in u
    assert "exit 2" in u                                                  # toute autre instance est refusee
    assert "StandardOutput=file:/run/secubox/kiosk-setup.log" in u
    assert "secubox-kiosk-setup@.service" in (KIOSK / "debian" / "rules").read_text()


def test_kiosk_enable_passe_par_l_unite_et_rend_le_motif(monkeypatch, tmp_path):
    from secubox_core import kiosk
    appels = []
    journal = tmp_path / "kiosk-setup.log"
    journal.write_text("setup: .xinitrc : Permission denied\n")
    monkeypatch.setattr(kiosk, "KIOSK_SETUP_SCRIPT", tmp_path / "script")
    (tmp_path / "script").write_text("#!/bin/sh\n")
    monkeypatch.setattr(kiosk, "KIOSK_SETUP_LOG", journal)
    monkeypatch.setattr(kiosk.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(kiosk.subprocess, "run", lambda cmd, **k: appels.append(cmd) or Res("", 1, ""))
    r = kiosk.kiosk_enable("x11")
    assert appels == [["systemctl", "start", "--wait", "secubox-kiosk-setup@enable-x11.service"]]
    assert r["success"] is False and "Permission denied" in r["error"]
    appels.clear(); monkeypatch.setattr(kiosk.subprocess, "run", lambda cmd, **k: appels.append(cmd) or Res("", 0, ""))
    assert kiosk.kiosk_disable()["success"] is True
    assert appels == [["systemctl", "start", "--wait", "secubox-kiosk-setup@disable.service"]]


def test_kiosk_enable_en_root_garde_l_appel_direct(monkeypatch, tmp_path):
    from secubox_core import kiosk
    appels = []
    (tmp_path / "script").write_text("#!/bin/sh\n")
    monkeypatch.setattr(kiosk, "KIOSK_SETUP_SCRIPT", tmp_path / "script")
    monkeypatch.setattr(kiosk.os, "geteuid", lambda: 0)
    monkeypatch.setattr(kiosk.subprocess, "run", lambda cmd, **k: appels.append(cmd) or Res("", 0, ""))
    assert kiosk.kiosk_enable("wayland")["success"] is True
    assert appels == [[str(tmp_path / "script"), "enable", "--wayland"]]

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3254 — box lite : le profil active le kiosque mais le paquet qui le configure manquait."""
import re
import sys
from pathlib import Path

PAQUETS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PAQUETS.parent / "common"))


def _relations(control: Path, champ: str) -> set[str]:
    texte = control.read_text()
    m = re.search(rf"^{champ}:(.*?)(?=^\S|\Z)", texte, re.M | re.S)
    if not m:
        return set()
    return {re.split(r"[\s(]", p.strip())[0] for p in m.group(1).split(",") if p.strip()}


def test_le_meta_lite_recommande_le_kiosque_que_son_profil_active():
    profil = (PAQUETS / "secubox-profiles" / "profiles" / "lite.toml").read_text()
    assert '"kiosk"' in profil
    control = PAQUETS / "secubox-lite" / "debian" / "control"
    assert "secubox-kiosk" in _relations(control, "Depends") | _relations(control, "Recommends")


def test_kiosque_absent_le_message_dit_quoi_installer(monkeypatch, tmp_path):
    from secubox_core import kiosk
    monkeypatch.setattr(kiosk, "KIOSK_SETUP_SCRIPT", tmp_path / "absent")
    for r in (kiosk.kiosk_enable("x11"), kiosk.kiosk_disable()):
        assert r["success"] is False
        assert "secubox-kiosk" in r["error"] and "apt install secubox-kiosk" in r["error"]
        assert "not installed" not in r["error"]

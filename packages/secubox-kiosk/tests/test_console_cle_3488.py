# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""La console du kiosque ne dépend pas de secubox-webos (#3488)."""
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def test_secret_cree_au_lancement_et_paquete():
    s = (R / "sbin/secubox-console-cle").read_text(encoding="utf-8")
    assert "/dev/urandom" in s and "chmod 0640" in s and "nginx -t" in s
    assert "secubox-console-cle" in (R / "systemd/secubox-kiosk.service.d/console.conf").read_text(encoding="utf-8")
    assert "sbin/secubox-console-cle" in (R / "debian/rules").read_text(encoding="utf-8")


def test_jamais_dans_une_image():
    t = (R.parents[1] / "image/lib/purger-secrets.sh").read_text(encoding="utf-8")
    assert "secrets/console.key" in t and "secubox-console/secret.conf" in t

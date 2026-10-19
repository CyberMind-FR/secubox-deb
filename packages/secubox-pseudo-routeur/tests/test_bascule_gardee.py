# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import subprocess
from pathlib import Path

CTL = Path(__file__).resolve().parents[1] / "sbin" / "pseudo-routeurctl"


def _ctl(tmp_path, *args, sonde_active):
    etat = tmp_path / "sonde.json"
    etat.write_text(json.dumps({"echecs_consecutifs": 0 if sonde_active else 3, "actif": sonde_active}))
    env = {"PATH": "/usr/bin:/bin", "SECUBOX_SONDE_ETAT": str(etat)}
    return subprocess.run(["bash", str(CTL), *args], env=env, capture_output=True, text=True, timeout=20)


def test_activer_refuse_sans_sonde_active(tmp_path):
    r = _ctl(tmp_path, "activer", sonde_active=False)
    assert r.returncode == 2
    assert "sonde" in r.stdout.lower() or "sonde" in r.stderr.lower()


def test_retour_freebox_fonctionne_meme_sonde_inactive(tmp_path):
    r = _ctl(tmp_path, "retour-freebox", sonde_active=False)
    assert r.returncode in (0, 1)  # peut echouer sur l'appel reseau en test, jamais sur la garde elle-meme
    assert "sonde" not in (r.stderr or "").lower()

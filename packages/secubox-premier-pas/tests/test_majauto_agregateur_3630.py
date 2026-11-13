# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""majauto : une seule relance de l'agrégateur quand un module qu'il sert a été mis à jour (#3630)."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
AIDE = PKG / "sbin" / "secubox-majauto-agregateur"

FAUX_DPKG = r"""#!/bin/sh
p=$3
[ -f "$FAUX/$p.liste" ] || exit 1
cat "$FAUX/$p.liste"
"""
FAUX_SYSTEMCTL = r"""#!/bin/sh
echo "$*" >> "$FAUX/appels"
case "$1" in show) cat "$FAUX/demarre" 2>/dev/null || echo "@1000" ;; esac
"""


def _env(tmp: Path, montes=("hub", "health-doctor")) -> dict:
    faux = tmp / "faux"
    faux.mkdir()
    for nom, txt in (("dpkg-query", FAUX_DPKG), ("systemctl", FAUX_SYSTEMCTL)):
        (faux / nom).write_text(txt)
        (faux / nom).chmod(0o755 | stat.S_IXUSR)
    (tmp / "aggregator.toml").write_text("modules = [" + ", ".join(f'"{m}"' for m in montes) + "]\n")
    env = dict(os.environ, FAUX=str(faux), SECUBOX_AGREGATEUR_TOML=str(tmp / "aggregator.toml"),
               SECUBOX_MAJAUTO_DPKG_QUERY=str(faux / "dpkg-query"), SECUBOX_MAJAUTO_SYSTEMCTL=str(faux / "systemctl"))
    return env


def _liste(tmp: Path, paquet: str, *chemins: str) -> None:
    (tmp / "faux" / f"{paquet}.liste").write_text("\n".join(chemins) + "\n")


def _run(env, *args):
    return subprocess.run([sys.executable, "-I", str(AIDE), *args], env=env, capture_output=True, text=True, timeout=30)


def _relances(tmp: Path) -> list[str]:
    p = tmp / "faux" / "appels"
    return [ligne for ligne in p.read_text().splitlines() if ligne.startswith("try-restart")] if p.exists() else []


def test_module_monte_mis_a_jour_une_seule_relance(tmp_path):
    env = _env(tmp_path)
    _liste(tmp_path, "secubox-health", "/usr/lib/secubox/health-doctor/api/main.py", "/usr/sbin/healthctl")
    _liste(tmp_path, "secubox-hub", "/usr/lib/secubox/hub/api/main.py")
    r = _run(env, "2000", "secubox-health", "secubox-hub")
    assert r.returncode == 0 and r.stdout.startswith("relance :"), r.stdout + r.stderr
    assert _relances(tmp_path) == ["try-restart --no-block secubox-aggregator.service"]


def test_secubox_core_declenche(tmp_path):
    env = _env(tmp_path)
    _liste(tmp_path, "secubox-core", "/usr/lib/python3/dist-packages/secubox_core/auth.py")
    assert _run(env, "2000", "secubox-core").stdout.startswith("relance :")


def test_module_non_monte_ou_statique_pas_de_relance(tmp_path):
    env = _env(tmp_path)
    _liste(tmp_path, "secubox-mail", "/usr/lib/secubox/mail/api/main.py")          # socket dédiée, pas monté
    _liste(tmp_path, "secubox-webos", "/usr/share/secubox/www/index.html")
    r = _run(env, "2000", "secubox-mail", "secubox-webos")
    assert r.stdout.startswith("pas de relance") and not _relances(tmp_path)


def test_deja_redemarre_pendant_la_passe(tmp_path):
    env = _env(tmp_path)
    (tmp_path / "faux" / "demarre").write_text("@3000\n")
    _liste(tmp_path, "secubox-hub", "/usr/lib/secubox/hub/api/main.py")
    r = _run(env, "2000", "secubox-hub")
    assert "déjà redémarré" in r.stdout and not _relances(tmp_path)


def test_paquet_agregateur_lui_meme_et_sans_toml(tmp_path):
    env = _env(tmp_path)
    _liste(tmp_path, "secubox-aggregator", "/usr/lib/secubox/aggregator/aggregator/main.py")
    assert not _relances(tmp_path) and _run(env, "2000", "secubox-aggregator").stdout.startswith("pas de relance")
    env["SECUBOX_AGREGATEUR_TOML"] = str(tmp_path / "absent.toml")
    _liste(tmp_path, "secubox-hub", "/usr/lib/secubox/hub/api/main.py")
    assert _run(env, "2000", "secubox-hub").stdout.startswith("pas de relance")


def test_simuler_et_arguments(tmp_path):
    env = _env(tmp_path)
    _liste(tmp_path, "secubox-hub", "/usr/lib/secubox/hub/api/main.py")
    assert "simulée" in _run(env, "2000", "secubox-hub", "--simuler").stdout and not _relances(tmp_path)
    assert _run(env, "pas-un-nombre", "secubox-hub").returncode == 2


def test_majauto_appelle_l_aide_apres_l_installation_et_paquet_l_installe():
    m = (PKG / "sbin" / "secubox-majauto").read_text()
    assert m.index('DEBUT=$(date +%s)') < m.index("install -y -q --only-upgrade")
    assert m.index('echo "fait"') < m.index('secubox-majauto-agregateur "$DEBUT"')
    assert "usr/sbin/secubox-majauto-agregateur" in (PKG / "debian" / "rules").read_text()

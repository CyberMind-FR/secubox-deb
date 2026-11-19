# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3826 : la rotation générale de /var/log/secubox tournait sous `su secubox secubox` et échouait dès que le dossier
partagé appartenait à root (tmpfiles de secubox-waf-ng) : « error creating output file audit.log.1.gz: Permission
denied » sur gk3, audit.log sans rotation depuis le 08/11 sur gk2. Elle tourne désormais en root, sans copytruncate."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REGLE = Path(__file__).resolve().parents[1] / "logrotate.d" / "secubox"


def _directives(texte: str) -> list[str]:
    return [ligne.split("#", 1)[0].strip() for ligne in texte.splitlines() if ligne.split("#", 1)[0].strip()]


def test_rotation_en_root_et_ajout_seul_preserve():
    d = _directives(REGLE.read_text(encoding="utf-8"))
    assert "su root root" in d
    assert not [x for x in d if re.fullmatch(r"su\s+secubox\b.*", x)]
    assert "copytruncate" not in d                      # CSPN : jamais de troncature du journal d'audit
    assert "create 0640 secubox secubox" in d           # propriétaire et mode du journal recréé inchangés
    assert REGLE.read_text(encoding="utf-8").startswith("# SPDX-License-Identifier: LicenseRef-CMSD-1.0")


def _unshare_root_possible() -> bool:
    if not (shutil.which("logrotate") and shutil.which("unshare")):
        return False
    r = subprocess.run(["unshare", "-r", "true"], capture_output=True, timeout=10, check=False)
    return r.returncode == 0


@pytest.mark.skipif(not _unshare_root_possible(), reason="logrotate ou espace de noms utilisateur indisponible")
def test_la_regle_tourne_dans_un_dossier_ouvert_au_groupe(tmp_path):
    """Vraie exécution de logrotate (root dans un espace de noms utilisateur, jamais le root du poste) : dossier 0775
    (cas toolbox, #2490), journal de la veille compressé, journal neuf recréé en 0640, rien de tronqué."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "audit.log").write_text('{"ts": "aujourd-hui"}\n')
    (logs / "audit.log.1").write_text('{"ts": "hier"}\n')
    os.chmod(logs, 0o775)
    regle = (REGLE.read_text(encoding="utf-8").replace("/var/log/secubox/*.log", f"{logs}/*.log")
             .replace("create 0640 secubox secubox", "create 0640 root root"))
    conf = tmp_path / "secubox.conf"
    conf.write_text(regle)
    conf.chmod(0o644)
    r = subprocess.run(["unshare", "-r", "logrotate", "-f", "-s", str(tmp_path / "etat"), str(conf)],
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stderr
    assert (logs / "audit.log.1").read_text() == '{"ts": "aujourd-hui"}\n'      # renommé, pas tronqué
    assert (logs / "audit.log.2.gz").is_file()                                  # la veille compressée
    assert (logs / "audit.log").stat().st_size == 0 and (logs / "audit.log").stat().st_mode & 0o777 == 0o640

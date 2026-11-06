# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3503 : à la création d'aggregator.toml, les modules configurés avant l'agrégateur sont déclarés."""
import re
import subprocess
from pathlib import Path

POSTINST = Path(__file__).parents[1] / "debian/postinst"


def test_declare_les_modules_installes(tmp_path):
    bloc = re.search(r"for module in .*?done\n", POSTINST.read_text(encoding="utf-8"), re.S).group(0)
    toml = tmp_path / "aggregator.toml"
    toml.write_text('modules = [\n    "cookies",\n]\n')
    (tmp_path / "usr/lib/secubox/hub/api").mkdir(parents=True)
    (tmp_path / "usr/lib/secubox/hub/api/main.py").touch()
    (tmp_path / "usr/lib/secubox/premier-pas/api").mkdir(parents=True)
    (tmp_path / "usr/lib/secubox/premier-pas/api/main.py").touch()
    bloc = bloc.replace("/usr/lib/secubox", f"{tmp_path}/usr/lib/secubox").replace("/etc/secubox/aggregator.toml", str(toml))
    subprocess.run(["sh", "-e", "-c", bloc], check=True)
    texte = toml.read_text()
    assert '"hub"' in texte and '"premier-pas"' in texte and '"cookies"' in texte and '"ad-guard"' not in texte

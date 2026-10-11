# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2310 : la ligne de commande que l'agent donne à `secubox-profilectl` est acceptée par la VRAIE CLI. Trouvé par le test VirtualBox : `unrecognized arguments: lite`
(le profil se passe par `--profile`, pas en positionnel) — aucun test ne confrontait la commande au vrai analyseur d'arguments."""
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(RACINE / "secubox-premier-pas"))
from autoload_agent import moteur as M  # noqa: E402


def test_l_appel_de_profilectl_passe_le_profil_par_son_option():
    src = (Path(M.__file__)).read_text(encoding="utf-8")
    assert '["secubox-profilectl", "apply", "--profile", etat["plan"]["profil"], "--yes"]' in src


def test_la_vraie_cli_accepte_la_commande_de_l_agent(monkeypatch):
    sys.path.insert(0, str(RACINE / "secubox-profiles"))
    cli = pytest.importorskip("api.cli")
    vu = {}
    monkeypatch.setattr(cli, "_cmd_apply", lambda a: vu.update(profil=a.profile, yes=a.yes) or 0)
    argv = ["secubox-profilectl", "apply", "--profile", "lite", "--yes"]               # la forme produite par Moteur._application
    assert cli.main(argv[1:]) == 0 and vu == {"profil": "lite", "yes": True}
    with pytest.raises(SystemExit):                                                      # la forme fautive est bel et bien refusée : le test aurait été rouge
        cli.main(["apply", "lite", "--yes"])

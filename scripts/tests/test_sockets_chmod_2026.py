# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2026 : uvicorn fait os.chmod(socket, 0o666) après le bind, l'umask n'y change rien. Un module qui veut
un socket en 660 DOIT le chmod après coup ; l'attente doit survivre à la charge du démarrage (la boucle de
15 s expirait et faisait échouer l'unité), et TimeoutStartSec doit couvrir cette attente."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
UNITES = {
    "devwatch": "packages/secubox-metanews/composants/devwatch/systemd/secubox-devwatch.service",
    "freeboxtv": "packages/secubox-media/composants/freeboxtv/systemd/secubox-freeboxtv.service",
    "voicestudio": "packages/secubox-voicestudio/systemd/secubox-voicestudio-api.service",
    "voice": "packages/secubox-voice/systemd/secubox-voice.service",
    "zia": "packages/secubox-zia/systemd/secubox-zia.service",
}


def _lire(chemin):
    return (RACINE / chemin).read_text()


def test_le_socket_est_chmod_660_apres_le_bind():
    for nom, chemin in UNITES.items():
        post = re.search(r"(?m)^ExecStartPost=.*$", _lire(chemin))
        assert post and f"chmod 660 /run/secubox/{nom}.sock" in post.group(0), nom


def test_l_attente_du_socket_survit_a_la_charge_du_demarrage():
    for nom, chemin in UNITES.items():
        texte = _lire(chemin)
        iterations = int(re.search(r"seq 1 (\d+)", texte).group(1))
        assert iterations >= 600, f"{nom} : {iterations} x 0,1 s = trop court (15 s a echoue sous charge)"
        delai = int(re.search(r"(?m)^TimeoutStartSec=(\d+)$", texte).group(1))
        assert delai > iterations / 10, f"{nom} : TimeoutStartSec={delai} s < attente de {iterations / 10:.0f} s"


def test_umask_ne_remplace_pas_le_chmod():
    # UMask=0007 sans chmod donnerait un socket en 666 (uvicorn) : jamais l'unique garde.
    for nom, chemin in UNITES.items():
        texte = _lire(chemin)
        assert not (re.search(r"(?m)^UMask=0007$", texte) and "chmod 660" not in texte), nom

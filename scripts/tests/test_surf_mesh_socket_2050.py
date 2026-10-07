# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2050 (M7, R5) : `surf` et `mesh` n'écoutent plus en TCP (9082, 8743) : socket Unix `/run/secubox/<module>.sock`, comme tous les modules.

Règle du projet : jamais de port TCP direct pour un module. Le socket est chmod 660 après le bind (uvicorn le crée en 666), la socket périmée
d'un run précédent est retirée par `ExecStartPre=+` (le parent /run/secubox est collant : on ne délie que ce qu'on possède)."""
import re
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
UNITES = {
    "surf": "packages/secubox-surf/systemd/secubox-surf.service",
    "mesh": "packages/secubox-mesh/systemd/secubox-mesh.service",
}


def _lire(chemin):
    return (RACINE / chemin).read_text()


def _actives(texte):
    return "\n".join(l for l in texte.splitlines() if not l.lstrip().startswith("#"))


def test_plus_de_port_tcp_dans_les_unites():
    for nom, chemin in UNITES.items():
        t = _actives(_lire(chemin))
        exec_start = re.search(r"(?m)^ExecStart=.*$", t).group(0)
        assert f"--uds /run/secubox/{nom}.sock" in exec_start, nom
        assert "--port" not in exec_start and "--host" not in exec_start, f"{nom} écoute encore en TCP : {exec_start}"


def test_socket_perime_retire_et_chmod_660_apres_le_bind():
    for nom, chemin in UNITES.items():
        t = _actives(_lire(chemin))
        assert f"ExecStartPre=+/bin/rm -f /run/secubox/{nom}.sock" in t, nom
        post = re.search(r"(?m)^ExecStartPost=.*$", t)
        assert post and f"chmod 660 /run/secubox/{nom}.sock" in post.group(0), nom
        assert int(re.search(r"seq 1 (\d+)", post.group(0)).group(1)) >= 600, f"{nom} : attente trop courte sous charge"
        assert int(re.search(r"(?m)^TimeoutStartSec=(\d+)$", t).group(1)) > 60, nom


def test_le_groupe_secubox_donne_acces_au_socket_et_run_secubox_est_inscriptible():
    for nom, chemin in UNITES.items():
        t = _actives(_lire(chemin))
        assert re.search(r"(?m)^Group=secubox\s*$", t), f"{nom} : nginx et l'agrégateur lisent le socket par le groupe secubox"
        assert "/run/secubox" in re.search(r"(?m)^ReadWritePaths=.*$", t).group(0), f"{nom} : ProtectSystem=strict interdit d'écrire le socket"


def test_le_vhost_de_surf_parle_au_socket():
    conf = _actives(_lire("packages/secubox-surf/nginx/surf.conf"))
    assert "proxy_pass http://unix:/run/secubox/surf.sock;" in conf
    assert "127.0.0.1:9082" not in conf


def test_la_mise_a_jour_de_surf_redemarre_le_service_avant_de_recharger_nginx():
    # sans cela, l'ancien processus (TCP) tourne encore alors que nginx vise déjà le socket : 502 jusqu'au prochain redémarrage
    post = _lire("packages/secubox-surf/debian/postinst")
    assert "try-restart secubox-surf.service" in post
    assert post.index("try-restart secubox-surf.service") < post.index("systemctl reload nginx")

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3450 : plus de partage d'indicateurs non signé ni d'écoute TCP."""
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]


def test_routes_de_partage_retirees():
    api = (RACINE / "api/main.py").read_text()
    assert "/mesh/ingest" not in api and "/mesh/gossip" not in api and "_mesh_loop" not in api


def test_socket_unix_et_aucun_port():
    unite = (RACINE / "systemd/secubox-threatmesh.service").read_text()
    assert "--uds /run/secubox/threatmesh.sock" in unite
    assert "--port" not in unite and "0.0.0.0" not in unite and "nft" not in unite
    assert "unix:/run/secubox/threatmesh.sock:" in (RACINE / "nginx/threatmesh.conf").read_text()


def test_migration_retire_table_et_indicateurs():
    post = (RACINE / "debian/postinst").read_text()
    assert "nft delete table inet secubox_threatmesh" in post
    assert "source LIKE 'mesh:%'" in post and "try-restart secubox-threatmesh" in post

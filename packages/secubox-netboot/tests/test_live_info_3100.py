# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — GET /live : comment netbooter une box, lu dans le boot.cmd réellement servi."""
import importlib
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
RACINE = ICI.parents[1]
sys.path.insert(0, str(ICI))
sys.path.insert(0, str(RACINE / "common"))

BOOT_CMD = """# SecuBox MOCHAbin — live réseau (#3079). Depuis le U-Boot usine, câble sur le WAN 1G (mvpp2-2) :
#   setenv ethact mvpp2-2; setenv ipaddr <ip libre>; setenv serverip 192.168.1.200
#   tftpboot ${loadaddr} mochabin-live/boot.scr; source ${loadaddr}
# Le live garde le réseau de l'initrd (ip=dhcp) : mv88e6xxx bloqué.
setenv serverip 192.168.1.200
setenv kernel_addr_r 0x08000000
tftpboot ${kernel_addr_r} mochabin-live/Image || exit
setenv bootargs console=ttyS0,115200 boot=live components fetch=http://192.168.1.200:8099/mochabin-live/filesystem.squashfs ip=dhcp
booti ${kernel_addr_r} ${ramdisk_addr_r}:${filesize} ${fdt_addr_r}
"""


@pytest.fixture
def racines(tmp_path):
    tftp, http = tmp_path / "tftp", tmp_path / "http"
    (tftp / "mochabin-live").mkdir(parents=True)
    (tftp / "mochabin-live" / "boot.cmd").write_text(BOOT_CMD)
    (tftp / "00504384fb2f").mkdir()                       # board publiée, pas un live : ignorée
    (http / "mochabin-live").mkdir(parents=True)
    (http / "mochabin-live" / "filesystem.squashfs").write_bytes(b"x")
    (http / "mochabin-live" / "images.txt").write_text(
        "secubox-isp-mochabin-trixie.img.gz 2669000177 " + "a" * 64 + "\n"
        "secubox-lite-mochabin-trixie.img.gz 2164961075 " + "b" * 64 + "\n"
        "../evil.img.gz 1 " + "c" * 64 + "\n"
        "ligne illisible\n")
    (http / "mochabin-live" / "secubox-isp-mochabin-trixie.img.gz.sig").write_bytes(b"s")
    return tftp, http


def _client(racines):
    from fastapi.testclient import TestClient
    sys.modules.pop("api.lot", None)
    sys.modules.pop("api.main", None)
    main = importlib.import_module("api.main")
    main.TFTP_ROOT, main.HTTP_ROOT = racines
    return main, TestClient(main.app)


def test_live_exige_une_session(racines):
    _, c = _client(racines)
    assert c.get("/live").status_code in (401, 403)


def test_live_decrit_le_boot_cmd_servi(racines):
    main, c = _client(racines)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    r = c.get("/live")
    assert r.status_code == 200
    lives = r.json()["lives"]
    assert [v["nom"] for v in lives] == ["mochabin-live"]
    live = lives[0]
    assert live["serveur"] == "192.168.1.200"
    assert live["http_base"] == "http://192.168.1.200:8099/mochabin-live"
    assert live["commandes"] == [
        "setenv ethact mvpp2-2; setenv ipaddr <ip libre>; setenv serverip 192.168.1.200",
        "tftpboot ${loadaddr} mochabin-live/boot.scr; source ${loadaddr}",
    ]
    assert live["squashfs"] is True
    assert live["images"] == [
        {"nom": "secubox-isp-mochabin-trixie.img.gz", "taille": 2669000177, "sha256": "a" * 64, "signee": True, "taille_brute": None},
        {"nom": "secubox-lite-mochabin-trixie.img.gz", "taille": 2164961075, "sha256": "b" * 64, "signee": False, "taille_brute": None},
    ]


def test_live_absent_liste_vide(tmp_path):
    main, c = _client((tmp_path / "rien", tmp_path / "rien2"))
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    assert c.get("/live").json() == {"lives": []}


def test_liens_symboliques_et_fifo_ignores(racines, tmp_path):
    import os
    tftp, http = racines
    secret = tmp_path / "secret.txt"
    secret.write_text("#   ligne-secrete\n")
    (tftp / "lien-live").mkdir()
    (tftp / "lien-live" / "boot.cmd").symlink_to(secret)        # fichier lié : jamais lu
    (tftp / "dossier-lie").symlink_to(tftp / "mochabin-live")    # dossier lié : ignoré
    (tftp / "fifo-live").mkdir()
    os.mkfifo(tftp / "fifo-live" / "boot.cmd")                    # FIFO : ne bloque pas
    main, c = _client(racines)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    lives = c.get("/live").json()["lives"]
    assert [v["nom"] for v in lives] == ["mochabin-live"]
    assert "ligne-secrete" not in str(lives)

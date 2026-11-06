# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Aucune image ne sort avec un secret de construction (#3518)."""
import json
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
LIB = RACINE / "image/lib/purger-secrets.sh"
BUILDERS = ["build-image", "build-live-usb", "build-rpi-usb", "build-ebin-live-usb", "build-mochabin-live-usb", "build-installer-iso"]


def purge(r):
    return subprocess.run(["bash", "-c", f'source "{LIB}"; purger_secrets "$1"', "_", str(r)], capture_output=True, text=True, timeout=30, check=False)


def test_purge(tmp_path):
    for f in ["etc/ssh/ssh_host_ed25519_key", "etc/ssh/ssh_host_rsa_key.pub", "etc/secubox/secrets/oidc/signing.pem", "etc/secubox/tls/key.pem",
              "etc/secubox/secrets/p2p/x", "etc/machine-id", "var/lib/dbus/machine-id", "etc/ssh/sshd_config"]:
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_text("secret")
    (tmp_path / "etc/secubox/users.json").write_text(json.dumps({"version": 2, "users": [{"username": "admin"}, {"username": "runnervmabc"}]}))
    assert purge(tmp_path).returncode == 0
    assert not list((tmp_path / "etc/ssh").glob("ssh_host_*")) and (tmp_path / "etc/ssh/sshd_config").exists()
    assert not (tmp_path / "etc/secubox/tls/key.pem").exists() and not (tmp_path / "etc/secubox/secrets/p2p").exists()
    assert (tmp_path / "etc/machine-id").read_text() == ""
    assert [u["username"] for u in json.loads((tmp_path / "etc/secubox/users.json").read_text())["users"]] == ["admin"]


def test_racine_refusee():
    assert purge("/").returncode == 2


@pytest.mark.parametrize("nom", BUILDERS)
def test_chaque_image_purge_avant_empaquetage(nom):
    s = (RACINE / f"image/{nom}.sh").read_text(encoding="utf-8")
    assert 'purger_secrets "${ROOTFS}"' in s
    if "mksquashfs \"${ROOTFS}\"" in s:
        assert s.index('purger_secrets "${ROOTFS}"') < s.rindex('mksquashfs "${ROOTFS}"')

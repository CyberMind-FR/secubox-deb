# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-lxc-decaler — un rootfs debootstrappé en root, pour un conteneur
non privilégié (#1729 : nextcloud et mail ne démarraient pas sur gk3)."""
import importlib.machinery
import importlib.util
import os
import stat
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "usr" / "sbin" / "secubox-lxc-decaler"


def charger():
    chargeur = importlib.machinery.SourceFileLoader("decaler", str(SCRIPT))
    spec = importlib.util.spec_from_loader("decaler", chargeur)
    m = importlib.util.module_from_spec(spec)
    chargeur.exec_module(m)
    return m


def rootfs(tmp_path):
    r = tmp_path / "rootfs"
    (r / "etc").mkdir(parents=True)
    (r / "usr" / "bin").mkdir(parents=True)
    (r / "usr" / "bin" / "passwd").write_text("x")
    os.chmod(r / "usr" / "bin" / "passwd", 0o4755)
    (r / "bin").symlink_to("usr/bin")
    return r


def test_decale_tout_preserve_setuid_ne_suit_pas_les_liens(tmp_path, monkeypatch):
    m = charger()
    r = rootfs(tmp_path)
    appels, modes = {}, {}
    monkeypatch.setattr(os, "lchown", lambda p, u, g: appels.__setitem__(str(p), (u, g)))
    monkeypatch.setattr(os, "chmod", lambda p, mo: modes.__setitem__(str(p), mo))
    n = m.decaler(str(r), 100000)
    uid, gid = os.getuid(), os.getgid()
    attendu = (uid + 100000, gid + 100000)
    for p in ("", "/etc", "/usr", "/usr/bin", "/usr/bin/passwd", "/bin"):
        assert appels[str(r) + p] == attendu, p
    assert n == len(appels) == 6
    assert modes == {str(r / "usr" / "bin" / "passwd"): 0o4755}   # setuid remis
    assert str(r / "bin" / "passwd") not in appels                   # lien non suivi


def test_idempotent_et_mode_etat(tmp_path, monkeypatch):
    m = charger()
    r = rootfs(tmp_path)
    monkeypatch.setattr(m, "TAILLE_PLAGE", 0)        # tout est « déjà décalé »
    monkeypatch.setattr(os, "lchown", lambda *a: (_ for _ in ()).throw(AssertionError("chown")))
    assert m.decaler(str(r), 100000) == 0
    m2 = charger()
    monkeypatch.setattr(os, "lchown", lambda *a: (_ for _ in ()).throw(AssertionError("--etat écrit")))
    assert m2.decaler(str(r), 100000, etat=True) == 6


def test_refuse_ce_qui_n_est_pas_un_rootfs(tmp_path):
    m = charger()
    assert m.main(["x", "/"]) == 2
    assert m.main(["x", str(tmp_path)]) == 2
    assert m.main(["x"]) == 2

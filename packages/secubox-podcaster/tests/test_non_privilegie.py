# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1759 — le podcaster repasse en `secubox`.

- L'assistant root ne suit AUCUN lien symbolique dans le rootfs de ytsas
  (fichier final ou répertoire parent) : sinon le root du conteneur lui
  ferait livrer les secrets de l'hôte.
- Un secret illisible pour le service passe par l'assistant ; une copie de
  cookies est privée (0600).
- Ni le mot de passe PeerTube ni le jeton ne passent par argv.
"""
import importlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1] / "sbin" / "podcasterctl"


def _ctl():
    loader = importlib.machinery.SourceFileLoader("podcasterctl", str(CTL))
    spec = importlib.util.spec_from_loader("podcasterctl", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _rootfs(tmp_path):
    d = tmp_path / "rootfs" / "var" / "lib" / "secubox" / "ytsas"
    d.mkdir(parents=True)
    return tmp_path / "rootfs", d


def test_assistant_lit_le_coffre_ordinaire(tmp_path):
    m = _ctl()
    racine, d = _rootfs(tmp_path)
    (d / "cookies.txt").write_text("# Netscape\n.youtube.com\tTRUE\n")
    assert m.lire_sans_lien(str(racine), m.YTSAS_CHEMIN).startswith(b"# Netscape")


def test_assistant_refuse_un_lien_final(tmp_path):
    m = _ctl()
    racine, d = _rootfs(tmp_path)
    cible = tmp_path / "secret-hote"
    cible.write_text("root:$6$HASH")
    os.symlink(cible, d / "cookies.txt")
    with pytest.raises(OSError):
        m.lire_sans_lien(str(racine), m.YTSAS_CHEMIN)


def test_assistant_refuse_un_repertoire_parent_lien(tmp_path):
    m = _ctl()
    racine = tmp_path / "rootfs"
    (racine / "var" / "lib").mkdir(parents=True)
    ailleurs = tmp_path / "hote" / "ytsas"
    ailleurs.mkdir(parents=True)
    (ailleurs / "cookies.txt").write_text("secret de l'hôte")
    os.symlink(tmp_path / "hote", racine / "var" / "lib" / "secubox")
    with pytest.raises(OSError):
        m.lire_sans_lien(str(racine), m.YTSAS_CHEMIN)


def test_assistant_verbes_nommes_seulement(tmp_path, capsys):
    m = _ctl()
    assert m.main(["podcasterctl"]) == 2
    assert m.main(["podcasterctl", "cat", "/etc/shadow"]) == 2
    assert m.main(["podcasterctl", "secret-peertube", "x"]) == 2


@pytest.fixture
def imp(monkeypatch):
    monkeypatch.delenv("PODCASTER_YT_COOKIES", raising=False)
    monkeypatch.delenv("YTSAS_COOKIES_HOST", raising=False)
    import api.importer as importer
    importlib.reload(importer)
    return importer


def test_secret_illisible_passe_par_l_assistant(imp, tmp_path, monkeypatch):
    illisible = tmp_path / "own.txt"
    illisible.write_text("# Netscape\n")
    monkeypatch.setattr(imp.os, "access", lambda p, mode: False)   # comme en secubox
    monkeypatch.setattr(imp, "YT_COOKIES", illisible)
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", tmp_path / "absent.txt")
    monkeypatch.setattr(imp, "COOKIES_PRIVES", tmp_path / ".yt-cookies.txt")
    vus = []

    def faux(cmd, **k):
        vus.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="# Netscape par assistant\n", stderr="")
    monkeypatch.setattr(imp.subprocess, "run", faux)
    p = imp._cookies_file()
    assert p == tmp_path / ".yt-cookies.txt"
    assert vus == [["sudo", "-n", imp.PODCASTERCTL, "cookies-youtube"]]
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert p.read_text().startswith("# Netscape par assistant")


def test_conf_peertube_par_l_assistant(imp, tmp_path, monkeypatch):
    monkeypatch.setattr(imp, "PT_SECRET", tmp_path / "absent.json")
    conf = {"base": "http://x", "host": "pt", "client_id": "i", "client_secret": "s",
            "username": "u", "password": "p", "channel": 1}
    monkeypatch.setattr(imp, "_assistant", lambda v: json.dumps(conf) if v == "secret-peertube" else None)
    assert imp._pt_conf() == conf


def test_aucun_secret_peertube_dans_argv(imp, monkeypatch, tmp_path):
    MDP, SEC, JETON = "MotDePasse-Tres-Secret", "ClientSecret-XYZ", "Jeton-ABC"
    conf = {"base": "http://pt.invalid", "host": "pt", "client_id": "i", "client_secret": SEC,
            "username": "u", "password": MDP, "channel": 1}
    argvs = []

    def faux_run(cmd, timeout=None, input=None):
        argvs.append((list(cmd), input))
        return subprocess.CompletedProcess(cmd, 0, stdout='{"video":{"shortUUID":"abc"}}', stderr="")
    monkeypatch.setattr(imp, "_run", faux_run)

    class Rep:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps({"access_token": JETON}).encode()
    envoye = {}

    def faux_urlopen(req, timeout=None):
        envoye["corps"] = req.data
        return Rep()
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", faux_urlopen)
    assert imp._pt_token(conf) == JETON
    assert MDP.encode() in envoye["corps"]            # dans le CORPS de la requête
    v = tmp_path / "v.mp4"
    v.write_bytes(b"x")
    imp._pt_upload(conf, JETON, v, "titre", "desc")
    for cmd, entree in argvs:
        assert not any(s in a for a in cmd for s in (MDP, SEC, JETON)), cmd
    assert any(entree and JETON in entree for _, entree in argvs)   # par stdin

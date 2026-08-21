# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: podcaster — résolution du fichier de cookies yt-dlp (#1100)
CyberMind — https://cybermind.fr

L'import YouTube échoue sans cookies (« confirm you're not a bot »). podcaster
doit réutiliser le coffre de ytsas : on vérifie l'ORDRE de priorité des
candidats, le repli, le rejet d'un fichier vide, et que `_ytdlp` insère bien
`--cookies <resolu>` dans la commande.
"""
import importlib

import pytest


@pytest.fixture
def imp(monkeypatch):
    # Neutralise tout override d'environnement entre les tests.
    monkeypatch.delenv("PODCASTER_YT_COOKIES", raising=False)
    monkeypatch.delenv("YTSAS_COOKIES_HOST", raising=False)
    import api.importer as importer
    importlib.reload(importer)
    return importer


def _write(p, content="# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tX\t1\n"):
    p.write_text(content)
    return p


def test_prefers_own_secret_over_ytsas_vault(imp, tmp_path, monkeypatch):
    own = _write(tmp_path / "own.txt")
    vault = _write(tmp_path / "vault.txt")
    monkeypatch.setattr(imp, "YT_COOKIES", own)
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", vault)
    assert imp._cookies_file() == own


def test_falls_back_to_ytsas_vault_when_own_absent(imp, tmp_path, monkeypatch):
    own = tmp_path / "missing.txt"                 # n'existe pas
    vault = _write(tmp_path / "vault.txt")
    monkeypatch.setattr(imp, "YT_COOKIES", own)
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", vault)
    assert imp._cookies_file() == vault            # « mêmes cookies que ytsas »


def test_env_override_wins(imp, tmp_path, monkeypatch):
    override = _write(tmp_path / "override.txt")
    own = _write(tmp_path / "own.txt")
    monkeypatch.setenv("PODCASTER_YT_COOKIES", str(override))
    monkeypatch.setattr(imp, "YT_COOKIES", own)
    importlib.reload(imp)                           # relit l'env au chargement
    monkeypatch.setattr(imp, "YT_COOKIES", own)
    assert imp._cookies_file() == override


def test_empty_file_is_skipped(imp, tmp_path, monkeypatch):
    own = _write(tmp_path / "own.txt", "")          # présent mais VIDE
    vault = _write(tmp_path / "vault.txt")
    monkeypatch.setattr(imp, "YT_COOKIES", own)
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", vault)
    assert imp._cookies_file() == vault             # un cookies vide ne masque pas ytsas


def test_none_when_no_candidate(imp, tmp_path, monkeypatch):
    monkeypatch.setattr(imp, "YT_COOKIES", tmp_path / "nope1.txt")
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", tmp_path / "nope2.txt")
    assert imp._cookies_file() is None


def test_ytdlp_splices_resolved_cookies(imp, tmp_path, monkeypatch):
    vault = _write(tmp_path / "vault.txt")
    monkeypatch.setattr(imp, "YT_COOKIES", tmp_path / "absent.txt")
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", vault)
    captured = {}
    monkeypatch.setattr(imp, "_run", lambda cmd, timeout=None: captured.setdefault("cmd", cmd))
    imp._ytdlp(["--dump-json", "URL"])
    cmd = captured["cmd"]
    assert cmd[0] == "yt-dlp"
    assert "--cookies" in cmd and str(vault) in cmd
    assert cmd[-2:] == ["--dump-json", "URL"]


def test_ytdlp_omits_cookies_when_none(imp, tmp_path, monkeypatch):
    monkeypatch.setattr(imp, "YT_COOKIES", tmp_path / "a.txt")
    monkeypatch.setattr(imp, "YTSAS_COOKIES_HOST", tmp_path / "b.txt")
    captured = {}
    monkeypatch.setattr(imp, "_run", lambda cmd, timeout=None: captured.setdefault("cmd", cmd))
    imp._ytdlp(["URL"])
    assert "--cookies" not in captured["cmd"]

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2635 — import YouTube : pas de ré-encodage inutile, et l'échec d'un flux est mémorisé et visible."""
import importlib
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def mods(tmp_path, monkeypatch):
    import api.store as st
    importlib.reload(st)
    st.DB_PATH = tmp_path / "p.db"
    st.init()
    import api.importer as imp
    monkeypatch.setattr(imp, "store", st)
    return st, imp


def test_l_audio_prefere_le_m4a_deja_aac_donc_un_simple_remux(mods, tmp_path, monkeypatch):
    """Sans -f, yt-dlp prend le flux le plus lourd (webm/opus) et ffmpeg le ré-encode en AAC : des dizaines de minutes par épisode."""
    _, imp = mods
    vu = []
    monkeypatch.setattr(imp, "_ytdlp", lambda args, timeout=None: vu.append(args) or subprocess.CompletedProcess(args, 0, "", ""))
    imp._download("abcdefghijk", tmp_path, want_video=False)
    args = vu[0]
    assert "-f" in args and args[args.index("-f") + 1].startswith("ba[ext=m4a]")
    assert "-x" in args and "m4a" in args


def test_les_colonnes_d_etat_existent_et_la_migration_est_idempotente(mods):
    st, _ = mods
    st.init()
    cols = {r[1] for r in st._conn().execute("PRAGMA table_info(feeds)")}
    assert {"last_error", "last_refresh"} <= cols


def test_un_flux_en_echec_garde_son_message_puis_l_efface_au_succes(mods):
    st, _ = mods
    fid = st.add_feed("youtube:x", {"title": "X", "site": "https://www.youtube.com/playlist?list=PLabc"})
    st.set_feed_status(fid, "yt-dlp : Sign in to confirm you're not a bot")
    f = next(f for f in st.list_feeds() if f["id"] == fid)
    assert "not a bot" in f["last_error"] and f["last_refresh"] > 0
    st.set_feed_status(fid, None)
    f = next(f for f in st.list_feeds() if f["id"] == fid)
    assert not f["last_error"] and f["last_refresh"] > 0


def test_un_import_qui_ne_trouve_rien_marque_le_flux_en_erreur(mods, monkeypatch, tmp_path):
    st, imp = mods
    url = "https://www.youtube.com/playlist?list=PLabc"
    fid = st.add_feed("youtube:x", {"title": "X", "site": url})
    monkeypatch.setattr(imp, "_enumerate", lambda u: [])
    imp.run_import(url, str(tmp_path / "media"), False, False)
    f = next(f for f in st.list_feeds() if f["id"] == fid)
    assert f["last_error"] and "rien" in f["last_error"].lower()


def test_un_import_reussi_efface_l_erreur(mods, monkeypatch, tmp_path):
    st, imp = mods
    url = "https://www.youtube.com/playlist?list=PLabc"
    fid = st.add_feed("youtube:x", {"title": "X", "site": url})
    st.set_feed_status(fid, "ancienne erreur")
    a = tmp_path / "a.m4a"
    a.write_bytes(b"x")
    monkeypatch.setattr(imp, "_enumerate", lambda u: [{"id": "abcdefghijk", "title": "T", "playlist": "X"}])
    monkeypatch.setattr(imp, "_download", lambda vid, wd, want_video: (None, a, {}, None))
    imp.run_import(url, str(tmp_path / "media"), False, False)
    f = next(f for f in st.list_feeds() if f["id"] == fid)
    assert not f["last_error"] and f["episodes"] == 1


def test_un_telechargement_en_echec_est_dit(mods, monkeypatch, tmp_path):
    st, imp = mods
    url = "https://www.youtube.com/playlist?list=PLabc"
    fid = st.add_feed("youtube:x", {"title": "X", "site": url})
    monkeypatch.setattr(imp, "_enumerate", lambda u: [{"id": "abcdefghijk", "title": "T", "playlist": "X"}])
    monkeypatch.setattr(imp, "_download", lambda vid, wd, want_video: (None, None, {}, None))
    imp.run_import(url, str(tmp_path / "media"), False, False)
    f = next(f for f in st.list_feeds() if f["id"] == fid)
    assert f["last_error"] and "1" in f["last_error"]


def test_la_route_reimporter_est_reservee_a_l_admin_et_connue():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()
    i = src.index('"/feeds/{fid}/refresh"')
    assert "require_jwt" in src[i - 20:i + 120]


def test_la_page_montre_l_erreur_copie_l_adresse_et_reimporte():
    html = (Path(__file__).resolve().parents[1] / "www" / "podcaster" / "index.html").read_text(encoding="utf-8")
    assert "f.last_error" in html and "copySrc(" in html and "refreshFeed(" in html
    assert "/refresh" in html and "navigator.clipboard.writeText" in html

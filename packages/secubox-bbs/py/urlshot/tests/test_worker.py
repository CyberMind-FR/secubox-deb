# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Tests du worker qui draine la file `urlshots` (#1120).

Aucun chromium réel, aucun réseau : `capture.capture_vignette` est
remplacé par une doublure. La base SQLite est un fichier `tmp_path`,
seedé avec le schéma exact de `internal/store/migrations/0023_urlshots.sql`
— jamais la vraie `/var/lib/secubox/bbs/index.db`."""
import sqlite3

from secubox_core import screenshots

import worker

_SCHEMA = """
CREATE TABLE urlshots (
  cle        TEXT PRIMARY KEY,
  url        TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'local',
  statut     TEXT NOT NULL DEFAULT 'pending',
  maj        INTEGER NOT NULL DEFAULT 0
);
"""


def _seed(db_path, rows):
    """Crée la table `urlshots` et y insère `rows` (cle, url), en pending,
    `maj` croissant selon l'ordre de la liste (reproduit l'ordre `ORDER BY
    maj` que `draine()` applique)."""
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_SCHEMA)
    for i, (cle, url) in enumerate(rows):
        conn.execute(
            "INSERT INTO urlshots(cle, url, maj) VALUES (?, ?, ?)", (cle, url, i)
        )
    conn.commit()
    conn.close()


def _statuts(db_path):
    conn = sqlite3.connect(str(db_path))
    rows = dict(conn.execute("SELECT cle, statut FROM urlshots").fetchall())
    conn.close()
    return rows


def test_draine_capture_ok_et_echec(tmp_path, monkeypatch):
    db_path = tmp_path / "index.db"
    cache_base = tmp_path / "cache"
    _seed(db_path, [
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "https://ok.example/"),
        ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "https://ko.example/"),
    ])

    def _fake_capture(url):
        if url == "https://ok.example/":
            return b"PNG1", True
        return None, False

    monkeypatch.setattr(worker.capture, "capture_vignette", _fake_capture)
    monkeypatch.setattr(worker.os, "getloadavg", lambda: (1.0, 1.0, 1.0))

    resultat = worker.draine(db_path=db_path, cache_base=cache_base)

    assert resultat == {"processed": 2, "ok": 1, "failed": 1}
    assert screenshots.png_path(cache_base, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").exists()
    assert not screenshots.png_path(cache_base, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").exists()

    statuts = _statuts(db_path)
    assert statuts["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] == "done"
    assert statuts["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] == "failed"


def test_draine_garde_de_charge_ne_traite_rien(tmp_path, monkeypatch):
    db_path = tmp_path / "index.db"
    cache_base = tmp_path / "cache"
    _seed(db_path, [("cccccccccccccccccccccccccccccccc"[:32], "https://ok.example/")])

    def _jamais_appele(url):
        raise AssertionError("capture_vignette ne doit pas être appelé sous charge")

    monkeypatch.setattr(worker.capture, "capture_vignette", _jamais_appele)
    monkeypatch.setattr(worker.os, "getloadavg", lambda: (99.0, 99.0, 99.0))

    resultat = worker.draine(db_path=db_path, cache_base=cache_base)

    assert resultat.get("skipped_load") is True
    statuts = _statuts(db_path)
    assert all(s == "pending" for s in statuts.values())


def test_draine_capture_qui_leve_marque_failed_sans_wedger(tmp_path, monkeypatch):
    db_path = tmp_path / "index.db"
    cache_base = tmp_path / "cache"
    _seed(db_path, [("dddddddddddddddddddddddddddddddd", "https://boom.example/")])

    def _leve(url):
        raise RuntimeError("panne simulée")

    monkeypatch.setattr(worker.capture, "capture_vignette", _leve)
    monkeypatch.setattr(worker.os, "getloadavg", lambda: (1.0, 1.0, 1.0))

    resultat = worker.draine(db_path=db_path, cache_base=cache_base)

    assert resultat == {"processed": 1, "ok": 0, "failed": 1}
    statuts = _statuts(db_path)
    assert statuts["dddddddddddddddddddddddddddddddd"] == "failed"
    assert not screenshots.png_path(cache_base, "dddddddddddddddddddddddddddddddd").exists()

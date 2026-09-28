# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Collecte des activités (#1560, P4) : BBS en lecture seule, diffusions du Hall."""
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secubox_core import sbxid as S  # noqa: E402
from api import activites as A  # noqa: E402

NOEUD = "did:plc:" + "b" * 32
T0 = 1_790_000_000


def bbs(p: Path):
    b = sqlite3.connect(p)
    b.executescript("""
      CREATE TABLE users (id INTEGER PRIMARY KEY, handle TEXT, disabled_at INTEGER);
      CREATE TABLE categories (id INTEGER PRIMARY KEY, slug TEXT, title TEXT, prive INTEGER, min_role_read TEXT);
      CREATE TABLE salon_communautes (category_id INTEGER, community_uuid TEXT);
      CREATE TABLE threads (id INTEGER PRIMARY KEY, category_id INTEGER, author_id INTEGER, title TEXT, visibility TEXT, created_at INTEGER);
      CREATE TABLE files (id INTEGER PRIMARY KEY, category_id INTEGER, owner_id INTEGER, name TEXT, visibility TEXT, created_at INTEGER, deleted_at INTEGER);
      INSERT INTO users VALUES (1,'Ani.skywalker',NULL),(2,'sbx-4e94',NULL),(3,'passerelle',5);
      INSERT INTO categories VALUES (1,'place','Place',0,'guest'),(2,'atelier','Atelier',0,'member'),
                                    (3,'intendance','Intendance',1,'guest'),(4,'secret','Secret',1,'guest');
      INSERT INTO threads VALUES (1,1,1,'Ancien',  'public', 1),
                                 (2,1,1,'Bonjour', 'public', 1790000100),
                                 (3,2,2,'Atelier', 'public', 1790000200),
                                 (4,3,1,'Budget',  'local',  1790000300),
                                 (5,4,1,'Personne','local',  1790000400),
                                 (7,1,3,'Import radio','public',1790000450);
      INSERT INTO files VALUES (1,1,1,'plan.pdf','public',1790000500,NULL),(2,1,1,'effacé','public',1790000600,1);
    """)
    return b


def test_collecte_bbs_et_diffusions(tmp_path):
    sbx = sqlite3.connect(":memory:", isolation_level=None)
    S.initialise(sbx)
    ani = "u-ani"
    sbx.execute("INSERT INTO sbx_users (user_uuid,pseudo,status,home_node,created_at) VALUES (?,?,?,?,1)",
                (ani, "ani.skywalker", "active", NOEUD))
    sbx.execute("INSERT INTO sbx_app_links VALUES (?,?,?,?)", (ani, "bbs", "Ani.skywalker", "Ani.skywalker"))
    k = S.cree_communaute(sbx, "Atelier", home_node=NOEUD, created_by=ani)
    b = bbs(tmp_path / "index.db")
    b.execute("INSERT INTO salon_communautes VALUES (3, ?)", (k,))
    b.commit(); b.close()
    (tmp_path / "hist.json").write_text(json.dumps([{"url": "/s/1", "titre": "Direct", "par": "", "ts": T0 + 700.5}]))
    sbx.execute("DELETE FROM sbx_activity")

    emis, cur = A.collecte(sbx, NOEUD, bbs_db=tmp_path / "index.db", diffusions=tmp_path / "hist.json",
                           curseurs={}, maintenant=T0 + 1000)
    # premier passage : 30 jours seulement (le fil 1 date de 1970) ; salon privé sans communauté : rien
    assert emis == {"bbs_post": 3, "file_shared": 1, "radio_live": 1}
    act = {(r[0], r[1], r[2]): r for r in sbx.execute(
        "SELECT kind, visibility, json_extract(context,'$.titre'), author, community_uuid, at FROM sbx_activity")}
    assert act[("bbs_post", "public", "Bonjour")][3] == ani                     # auteur lié → sa personne
    assert act[("bbs_post", "public", "Bonjour")][5] == 1790000100             # l'heure de l'événement
    assert act[("bbs_post", "node", "Atelier")][3] == "bbs:sbx-4e94"           # salon réservé aux membres
    assert act[("bbs_post", "community", "Budget")][4] == k                    # privé ouvert à la communauté
    assert not any(t == "Personne" for (_, _, t) in act)                       # privé sans communauté
    assert ("radio_live", "node", "Direct") in act
    assert not any(t == "Import radio" for (_, _, t) in act)                   # compte désactivé : pas un geste
    # second passage : rien de neuf, rien d'émis ; un nouveau fil suit
    emis, cur = A.collecte(sbx, NOEUD, bbs_db=tmp_path / "index.db", diffusions=tmp_path / "hist.json",
                           curseurs=cur, maintenant=T0 + 2000)
    assert emis == {"bbs_post": 0, "file_shared": 0, "radio_live": 0}
    b = sqlite3.connect(tmp_path / "index.db")
    b.execute("INSERT INTO threads VALUES (6,1,1,'Suite','public',1790001000)"); b.commit(); b.close()
    emis, _ = A.collecte(sbx, NOEUD, bbs_db=tmp_path / "index.db", diffusions=tmp_path / "hist.json",
                         curseurs=cur, maintenant=T0 + 3000)
    assert emis["bbs_post"] == 1

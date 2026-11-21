# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Socle de la veille V2 (#3719) : veille.db, migrations, rétention, boucles, garde d'espace, paquet."""
import asyncio
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from veille import base, retention
from veille.service import Boucle, Veille

PAQUET = Path(__file__).resolve().parents[1]
MIGRATIONS = PAQUET / "migrations"
TABLES = {"schema_migrations", "curseurs", "evenements", "campagnes", "blocs", "incidents", "incident_preuves",
          "mesures", "audit_chaine", "dossiers", "dossier_incidents", "dossier_evenements", "dossier_membres"}
MAINTENANT = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def _rfc(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_migrations_idempotentes_et_sauvegarde(tmp_path):
    chemin = tmp_path / "veille.db"
    db = base.ouvrir(chemin, MIGRATIONS)
    noms = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert TABLES <= noms
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert db.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert base.migrer(db, MIGRATIONS) == []                       # rien à refaire
    assert db.execute("SELECT version FROM schema_migrations ORDER BY 1").fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,), (7,), (8,), (9,)]
    assert not list(tmp_path.glob("veille.db.avant-*"))            # base neuve : rien à sauvegarder
    db.execute("INSERT INTO curseurs(source, etat) VALUES ('waf_alertes', 'ok')")
    db.commit()
    db.close()
    # Une migration 0098 arrive : sauvegarde veille.db.avant-0098 puis application ; une seule sauvegarde gardée.
    dossier = tmp_path / "mig"
    dossier.mkdir()
    for f in MIGRATIONS.glob("*.sql"):
        (dossier / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    (dossier / "0098-test.sql").write_text("CREATE TABLE essai (x INTEGER);", encoding="utf-8")
    db = base.ouvrir(chemin, dossier)
    assert [v for (v,) in db.execute("SELECT version FROM schema_migrations ORDER BY 1")] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 98]
    sauv = list(tmp_path.glob("veille.db.avant-*"))
    assert [s.name for s in sauv] == ["veille.db.avant-0098"]
    ancienne = sqlite3.connect(sauv[0])
    assert ancienne.execute("SELECT source FROM curseurs").fetchall() == [("waf_alertes",)]
    ancienne.close()
    (dossier / "0099-test.sql").write_text("CREATE TABLE essai2 (x INTEGER);", encoding="utf-8")
    assert base.migrer(db, dossier) == [99]
    assert [s.name for s in tmp_path.glob("veille.db.avant-*")] == ["veille.db.avant-0099"]
    db.close()


def test_migration_en_echec_annulee(tmp_path):
    dossier = tmp_path / "mig"
    dossier.mkdir()
    (dossier / "0001-a.sql").write_text("CREATE TABLE a (x INTEGER);", encoding="utf-8")
    (dossier / "0002-b.sql").write_text("CREATE TABLE b (x INTEGER); CREATE TABLE a (x INTEGER);", encoding="utf-8")
    with pytest.raises(sqlite3.Error):
        base.ouvrir(tmp_path / "v.db", dossier)
    db = sqlite3.connect(tmp_path / "v.db")
    noms = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "b" not in noms and "a" in noms
    assert db.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]


def _evenement(db, i, horodatage):
    db.execute(
        "INSERT INTO evenements(id, source, noeud, horodatage, famille, gravite, empreinte, cree_le) "
        "VALUES (?, 'sbxwaf', 'gk2', ?, 'scanners', 'low', ?, ?)", (f"e{i}", horodatage, f"emp{i}", horodatage))


def test_retention_par_lots(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db", MIGRATIONS)
    vieux = _rfc(MAINTENANT - timedelta(days=31))
    recent = _rfc(MAINTENANT - timedelta(days=29))
    for i in range(2500):
        _evenement(db, i, vieux)
    _evenement(db, 9000, recent)
    # Un événement ancien mais preuve d'un incident récent est gardé (clé étrangère) ; l'incident ancien part.
    _evenement(db, 9001, vieux)
    db.execute("INSERT INTO incidents(id, regle, cle, titre, etat, gravite, sources_json, premiere_vue, derniere_vue, "
               "cree_le, maj_le) VALUES ('i-recent', 'r', 'k', 't', 'ouvert', 'low', '[]', ?, ?, ?, ?)",
               (recent, recent, recent, recent))
    db.execute("INSERT INTO incident_preuves VALUES ('i-recent', 'e9001')")
    ancien = _rfc(MAINTENANT - timedelta(days=366))
    db.execute("INSERT INTO incidents(id, regle, cle, titre, etat, gravite, sources_json, premiere_vue, derniere_vue, "
               "cree_le, maj_le) VALUES ('i-vieux', 'r', 'k2', 't', 'clos', 'low', '[]', ?, ?, ?, ?)",
               (ancien, ancien, ancien, ancien))
    db.execute("INSERT INTO mesures(horodatage, erreurs) VALUES (?, 0)", (vieux,))
    db.execute("INSERT INTO mesures(horodatage, erreurs) VALUES (?, 0)", (recent,))
    db.commit()
    requetes = []
    db.set_trace_callback(lambda s: requetes.append(s) if s.startswith("DELETE") else None)
    res = retention.purger(db, MAINTENANT)
    assert res == {"evenements": 2500, "incidents": 1, "mesures": 1, "dossiers": 0, "pays": 0}
    assert len([r for r in requetes if "evenements" in r]) >= 3          # lots de 1 000
    assert db.execute("SELECT count(*) FROM evenements").fetchone()[0] == 2
    assert db.execute("SELECT id FROM incidents").fetchall() == [("i-recent",)]
    assert db.execute("SELECT count(*) FROM mesures").fetchone()[0] == 1
    assert retention.purger(db, MAINTENANT) == {"evenements": 0, "incidents": 0, "mesures": 0, "dossiers": 0, "pays": 0}
    assert (tmp_path / "veille.db").exists()                              # jamais supprimée


class Horloge:
    def __init__(self):
        self.t = MAINTENANT

    def __call__(self):
        return self.t


def test_boucle_en_erreur_continue(tmp_path, caplog):
    db = base.ouvrir(tmp_path / "veille.db", MIGRATIONS)
    appels = {"mauvaise": 0, "bonne": 0}

    async def mauvaise():
        appels["mauvaise"] += 1
        raise RuntimeError("boum")

    async def bonne():
        appels["bonne"] += 1

    async def scenario():
        v = Veille(db, Horloge(), [Boucle("mauvaise", 0.01, mauvaise), Boucle("bonne", 0.01, bonne)],
                   libre_octets=lambda: 10 * 2**30)
        tache = asyncio.create_task(v.executer())
        await asyncio.sleep(0.15)
        v.arreter()
        await asyncio.wait_for(tache, 2)

    with caplog.at_level("ERROR"):
        asyncio.run(scenario())
    assert appels["mauvaise"] >= 2 and appels["bonne"] >= 2            # réessayée, jamais fatale, sans gêner l'autre
    assert any("mauvaise" in r.getMessage() for r in caplog.records)


def test_ecriture_concurrente_api_veille(tmp_path):
    chemin = tmp_path / "veille.db"
    veille = base.ouvrir(chemin, MIGRATIONS)
    api = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=5)
    api.execute("PRAGMA busy_timeout = 5000")
    _evenement(veille, 1, _rfc(MAINTENANT))
    veille.commit()
    curseur = api.execute("SELECT id FROM evenements")               # lecture en cours (instantané WAL)
    assert curseur.fetchone() == ("e1",)
    _evenement(veille, 2, _rfc(MAINTENANT))                          # écriture PENDANT la lecture : aucun verrou
    veille.commit()
    assert curseur.fetchall() == []
    assert api.execute("SELECT count(*) FROM evenements").fetchone()[0] == 2
    # Un second écrivain (décision humaine de l'API) attend le verrou au lieu d'échouer.
    ecrivain = base.ouvrir(chemin, MIGRATIONS)
    ecrivain.execute("INSERT INTO curseurs(source, etat) VALUES ('humain', 'ok')")
    ecrivain.commit()
    assert veille.execute("SELECT count(*) FROM curseurs").fetchone()[0] == 1


def test_garde_espace_suspend(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db", MIGRATIONS)
    libre = {"v": 10 * 2**30}
    collectes = []
    horloge = Horloge()

    async def collecte():
        collectes.append(1)

    async def autre():
        collectes.append("autre")

    async def scenario():
        v = Veille(db, horloge, [Boucle("collecte", 0.01, collecte, collecte=True), Boucle("autre", 0.01, autre)],
                   libre_octets=lambda: libre["v"], seuil_octets=2**30)
        t = asyncio.create_task(v.executer())
        await asyncio.sleep(0.08)
        assert not v.suspendue and 1 in collectes
        libre["v"] = 2**29                                           # sous 1 Gio
        await asyncio.sleep(0.08)
        assert v.suspendue
        avant = collectes.count(1)
        await asyncio.sleep(0.1)
        assert collectes.count(1) == avant                           # collecte arrêtée, les autres boucles continuent
        assert "autre" in collectes
        assert v.etat()["espace"] == "suspendu"
        libre["v"] = 2**31
        await asyncio.sleep(0.1)
        assert not v.suspendue and collectes.count(1) > avant
        v.arreter()
        await asyncio.wait_for(t, 2)

    asyncio.run(scenario())
    assert db.execute("SELECT count(*) FROM audit_chaine").fetchone()[0] >= 0


# ── paquet ──

def test_unite_veille_durcie():
    texte = (PAQUET / "systemd" / "secubox-ai-veille.service").read_text(encoding="utf-8")
    code = "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))
    for ligne in ("User=secubox-ai", "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                  "ProtectKernelTunables=yes", "ProtectControlGroups=yes", "RestrictSUIDSGID=yes",
                  "LockPersonality=yes", "UMask=0027", "AppArmorProfile=secubox-ai-veille",
                  "CapabilityBoundingSet=", "SQLITE_TMPDIR=/var/lib/secubox/ai/tmp"):
        assert ligne in code, ligne
    assert re.search(r"^ReadWritePaths=/var/lib/secubox/ai$", code, re.M)
    assert "AF_INET" in code and "root" not in code.split("User=")[1].splitlines()[0]
    assert "ExecStart=/usr/sbin/secubox-ai-veille" in code


def test_profil_veille_enforce_et_borne():
    texte = (PAQUET / "apparmor" / "secubox-ai-veille").read_text(encoding="utf-8")
    code = "\n".join(x for x in texte.splitlines() if not x.lstrip().startswith("#"))
    assert re.search(r"^profile secubox-ai-veille \{", code, re.M) and "complain" not in code
    assert "/var/lib/secubox/ai/** rwk," in code
    assert "/etc/secubox/secrets/" not in code or "ai-lecture.key" in code
    assert not re.search(r"/etc/secubox/\*", code)


def test_rules_et_postinst_installent_la_veille():
    rules = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
    post = (PAQUET / "debian" / "postinst").read_text(encoding="utf-8")
    for x in ("cp -r veille debian/secubox-ai/usr/lib/secubox/ai/", "cp -r migrations debian/secubox-ai/usr/lib/secubox/ai/",
              "sbin/secubox-ai-veille", "systemd/secubox-ai-veille.service", "apparmor/secubox-ai-veille"):
        assert x in rules, x
    assert "secubox-ai-veille.service" in post and "secubox-ai-veille" in post.split("for _p in")[1].split(";")[0]


def test_sbin_veille_executable():
    s = PAQUET / "sbin" / "secubox-ai-veille"
    assert s.read_text(encoding="utf-8").startswith("#!/usr/bin/python3 -IB")


def test_sauvegarde_en_echec_garde_l_ancienne_et_n_applique_pas(tmp_path):
    chemin = tmp_path / "veille.db"
    db = base.ouvrir(chemin, MIGRATIONS)
    db.close()
    dossier = tmp_path / "mig"
    dossier.mkdir()
    for f in MIGRATIONS.glob("*.sql"):
        (dossier / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    (dossier / "0098-test.sql").write_text("CREATE TABLE essai (x INTEGER);", encoding="utf-8")
    db = base.ouvrir(chemin, dossier)
    db.close()
    ancienne = tmp_path / "veille.db.avant-0098"
    assert ancienne.exists()
    (dossier / "0099-test.sql").write_text("CREATE TABLE essai2 (x INTEGER);", encoding="utf-8")
    db = base._connecter(chemin)

    class Faux:
        def __init__(self, reel):
            self.reel = reel

        def backup(self, dst):
            raise sqlite3.OperationalError("disque plein")

        def __getattr__(self, n):
            return getattr(self.reel, n)

    with pytest.raises(sqlite3.OperationalError):
        base.migrer(Faux(db), dossier)
    assert ancienne.exists()
    assert [s.name for s in tmp_path.glob("veille.db.avant-*")] == ["veille.db.avant-0098"]
    assert db.execute("SELECT 1 FROM schema_migrations WHERE version = 99").fetchone() is None
    db.close()


def test_par_lots_rollback_sur_exception():
    class Db:
        in_transaction = False
        appels = []

        def execute(self, sql, params=()):
            self.appels.append(sql)
            if sql == "BEGIN IMMEDIATE":
                self.in_transaction = True
                return None
            raise sqlite3.OperationalError("boom")

        def rollback(self):
            self.in_transaction = False
            self.appels.append("ROLLBACK")

    db = Db()
    with pytest.raises(sqlite3.OperationalError):
        retention._par_lots(db, "DELETE FROM x", ())
    assert db.appels[-1] == "ROLLBACK" and not db.in_transaction

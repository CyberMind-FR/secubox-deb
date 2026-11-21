# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Rétention bornée de veille.db et garde d'espace sur toutes les boucles (#3725) : chaque borne, jamais une ligne
vivante, ordre des clés étrangères, plafonds de secours, garde et hystérésis."""
import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from veille import base, retention
from veille.service import Boucle, Veille

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


def rfc(jours):
    return (NOW - timedelta(days=jours)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def db(tmp_path):
    d = base.ouvrir(tmp_path / "veille.db")
    yield d
    d.close()


def dossier(db, did, jours, **kw):
    h = rfc(jours)
    db.execute("INSERT INTO dossiers(id, cle, type, gravite, premiere_vue, derniere_vue, maj_le) "
               "VALUES (?, ?, 'acteur', 'low', ?, ?, ?)", (did, f"k-{did}", h, h, h))


def incident(db, iid, jours=0):
    h = rfc(jours)
    db.execute("INSERT INTO incidents(id, regle, cle, titre, etat, gravite, sources_json, premiere_vue, derniere_vue, "
               "cree_le, maj_le) VALUES (?, 'r', ?, 't', 'ouvert', 'low', '[]', ?, ?, ?, ?)", (iid, iid, h, h, h, h))


def proposition(db, pid, jours, etat="faite", geste="ban", dossier_id=None, reference=None, cible=None):
    h = rfc(jours)
    db.execute("INSERT INTO propositions(id, dossier_id, geste, cible, mode, politique, motif, etat, expire_le, cree_le, "
               "maj_le, reference) VALUES (?, ?, ?, ?, 'clic', 'p', 'm', ?, ?, ?, ?, ?)",
               (pid, dossier_id, geste, cible or f"198.51.100.{abs(hash(pid)) % 250}", etat, h, h, h, reference))


def action(db, aid, pid, jours, etat="faite", fin=None):
    h = rfc(jours)
    db.execute("INSERT INTO actions(id, proposition_id, geste, cible, mode, etat, jti, cle, fin_gk2, envoyee_le, repondue_le) "
               "VALUES (?, ?, 'ban', 'c', 'clic', ?, 'j', 'k', ?, ?, ?)", (aid, pid, etat, fin, h, h))


def ids(db, table):
    return {r[0] for r in db.execute(f"SELECT id FROM {table}")}


# ── 1. dossiers ──

def test_dossier_sans_trace_30_jours_avec_trace_365(db):
    dossier(db, "nu-vieux", 31)
    dossier(db, "nu-jeune", 29)
    dossier(db, "inc-31", 31)
    incident(db, "i1")
    db.execute("INSERT INTO dossier_incidents VALUES ('inc-31', 'i1')")
    dossier(db, "act-31", 31)
    proposition(db, "pa", 31, dossier_id="act-31")
    action(db, "aa", "pa", 31)
    dossier(db, "inc-366", 366)
    db.execute("INSERT INTO dossier_incidents VALUES ('inc-366', 'i1')")
    # liens de l'ancien dossier nu : partent en cascade avec lui
    db.execute("INSERT INTO analyses(id, dossier_id, etat, resume, cree_le) VALUES ('an1', 'nu-vieux', 'valide', 'r', ?)", (rfc(31),))
    db.commit()
    res = retention.purger(db, NOW)
    assert res["dossiers"] == 2
    assert ids(db, "dossiers") == {"nu-jeune", "inc-31", "act-31"}
    assert ids(db, "analyses") == set()                              # cascade


def test_dossier_vivant_jamais_purge(db):
    for d in ("prop", "redesc", "travail"):
        dossier(db, d, 400)
    proposition(db, "pv", 1, etat="proposee", dossier_id="prop")
    db.execute("INSERT INTO redescentes(id, dossier_id, acteur, demandee_le) VALUES ('r1', 'redesc', 'a', ?)", (rfc(1),))
    db.execute("INSERT INTO travaux(genre, objet_id, etat, disponible_le, cree_le) VALUES ('analyser', 'travail', 'attente', 0, ?)",
               (rfc(1),))
    dossier(db, "mort", 400)
    db.commit()
    retention.purger(db, NOW)
    assert ids(db, "dossiers") == {"prop", "redesc", "travail"}


# ── 2, 3. actions et propositions : ordre des clés étrangères, chaînes, bans vivants ──

def test_actions_avant_propositions_et_seuils(db):
    proposition(db, "p-old", 400)
    action(db, "a-old", "p-old", 400)                     # action close de 400 j : part, puis sa proposition
    proposition(db, "p-100", 100)                         # sans action, close, 100 j > 90 : part
    proposition(db, "p-60", 60)                           # 60 j : reste
    proposition(db, "p-act", 100)
    action(db, "a-act", "p-act", 100)                     # action de 100 j < 365 : la proposition reste avec elle
    db.execute("INSERT INTO approbations(id, proposition_id, version, acteur, decision, cree_le) VALUES ('ap', 'p-100', 1, 'x', 'approuver', ?)",
               (rfc(100),))
    db.commit()
    res = retention.purger(db, NOW)                       # foreign_keys = ON : un mauvais ordre lèverait IntegrityError
    assert res["actions"] == 1 and res["propositions"] == 2
    assert ids(db, "actions") == {"a-act"} and ids(db, "propositions") == {"p-60", "p-act"}
    assert ids(db, "approbations") == set()               # cascade


def test_ban_vivant_et_proposition_en_vol_jamais_purges(db):
    proposition(db, "ban-vivant", 400)
    action(db, "a-vivant", "ban-vivant", 400, fin=int((NOW + timedelta(hours=2)).timestamp()))
    proposition(db, "envoi", 400, etat="envoyee")
    action(db, "a-envoi", "envoi", 400, etat="envoi")
    proposition(db, "a-decider", 400, etat="proposee")
    proposition(db, "approuvee", 400, etat="approuvee")
    db.commit()
    retention.purger(db, NOW)
    assert ids(db, "actions") == {"a-vivant", "a-envoi"}
    assert ids(db, "propositions") == {"ban-vivant", "envoi", "a-decider", "approuvee"}


def test_chaine_de_reference_vivante_protege_le_ban(db):
    # ban ancien, mais sa prolongation est jeune : ni la proposition du ban ni son action ne partent.
    proposition(db, "ban", 500)
    action(db, "a-ban", "ban", 500, fin=int((NOW - timedelta(days=400)).timestamp()))
    proposition(db, "prol", 10, geste="prolonger", reference="ban")
    # ban ancien dont la seule suite est ancienne aussi : part.
    proposition(db, "ban2", 500, cible="198.51.100.7")
    proposition(db, "unban2", 400, geste="unban", reference="ban2", cible="198.51.100.7")
    db.commit()
    retention.purger(db, NOW)
    assert {"ban", "prol"} <= ids(db, "propositions") and "a-ban" in ids(db, "actions")
    assert "ban2" not in ids(db, "propositions") and "unban2" not in ids(db, "propositions")
    # une référence vivante protège aussi
    proposition(db, "ban3", 500, cible="198.51.100.8")
    proposition(db, "prol3", 1, geste="prolonger", reference="ban3", etat="proposee", cible="198.51.100.8")
    db.commit()
    retention.purger(db, NOW)
    assert "ban3" in ids(db, "propositions")


# ── 4. adresses, filtres ──

def test_adresses_et_filtres(db):
    db.executemany("INSERT INTO acteurs_adresses VALUES (?, 'A', ?)", [("1.1.1.1", rfc(31)), ("2.2.2.2", rfc(29))])
    for fid, etat, j in (("f-retire", "retire", 91), ("f-retire-jeune", "retire", 89), ("f-confirme", "confirme", 400),
                         ("f-essai", "essai", 400), ("f-rejete", "rejete", 100)):
        db.execute("INSERT INTO filtres(id, outil, cve, corps_json, etat, envoye_le, maj_le) VALUES (?, 'o', 'c', '{}', ?, ?, ?)",
                   (fid, etat, rfc(j), rfc(j)))
    db.commit()
    retention.purger(db, NOW)
    assert {r[0] for r in db.execute("SELECT ip FROM acteurs_adresses")} == {"2.2.2.2"}
    assert ids(db, "filtres") == {"f-retire-jeune", "f-confirme", "f-essai"}


# ── 5. audit_chaine ──

def _audit(db, jours, relais=False):
    d = json.dumps({"relais": True} if relais else {})
    db.execute("INSERT INTO audit_chaine(horodatage, acteur, operation, resultat, details_json, empreinte) "
               "VALUES (?, 'a', 'o', 'ok', ?, 'e')", (rfc(jours), d))


def test_audit_365_jours_seulement_le_relaye(db):
    _audit(db, 400)                      # 1 : ancien, pas de relais : part
    _audit(db, 400, relais=True)         # 2 : ancien, à relayer (curseur 0) : reste, et bloque la suite
    _audit(db, 400)                      # 3 : ancien mais derrière une ligne non relayée : reste
    _audit(db, 10)                       # 4 : jeune
    db.commit()
    retention.purger(db, NOW)
    assert [r[0] for r in db.execute("SELECT id FROM audit_chaine ORDER BY id")] == [2, 3, 4]
    db.execute("INSERT INTO executeur_etat VALUES ('audit_relai', '2', ?)", (rfc(0),))
    db.commit()
    retention.purger(db, NOW)
    assert [r[0] for r in db.execute("SELECT id FROM audit_chaine ORDER BY id")] == [4]   # 2, 3 partis ; jamais la tête


# ── 6. plafonds de secours ──

def test_plafonds_purgent_le_plus_ancien_clos_jamais_le_vivant(db, monkeypatch):
    monkeypatch.setitem(retention.PLAFONDS, "propositions", 3)
    monkeypatch.setitem(retention.PLAFONDS, "dossiers", 2)
    monkeypatch.setitem(retention.PLAFONDS, "actions", 1)
    monkeypatch.setitem(retention.PLAFONDS, "analyses", 1)
    for i, j in enumerate((10, 20, 30, 40)):             # 4 propositions closes < 90 j, plafond 3
        proposition(db, f"c{i}", j)
    proposition(db, "vivante", 80, etat="proposee")      # la plus vieille de toutes mais en vol
    for i, j in enumerate((5, 6, 7)):
        dossier(db, f"d{i}", j)
    proposition(db, "pd", 1, etat="envoyee", dossier_id="d2")      # d2 vivant (le plus ancien)
    for i, j in enumerate((1, 2, 3)):
        proposition(db, f"pa{i}", j)
        action(db, f"ac{i}", f"pa{i}", j)
    for i in range(3):
        db.execute("INSERT INTO analyses(id, dossier_id, etat, resume, cree_le) VALUES (?, 'd0', 'valide', 'r', ?)",
                   (f"an{i}", rfc(i + 1)))
    db.commit()
    res = retention.purger(db, NOW)
    assert "c3" not in ids(db, "propositions") and "vivante" in ids(db, "propositions")
    assert res["plafond_dossiers"] == 1 and ids(db, "dossiers") == {"d0", "d2"}   # d1 (plus ancien éligible après d2 vivant)
    assert len(ids(db, "actions")) == 1 and ids(db, "analyses") == {"an0"}
    # plafond dépassé mais rien d'éligible : aucune ligne vivante n'est touchée, pas de boucle infinie
    monkeypatch.setitem(retention.PLAFONDS, "propositions", 0)
    retention.purger(db, NOW)
    assert "vivante" in ids(db, "propositions")


# ── 7. garde d'espace ──

class Horloge:
    def __call__(self):
        return NOW


def test_garde_suspend_toutes_les_boucles_sauf_retention_avec_hysteresis(tmp_path):
    db = base.ouvrir(tmp_path / "veille.db")
    libre = {"v": 10 * 2**30}
    tours = {n: 0 for n in ("collecte", "correlation", "analyse", "reponses", "apprentissage", "pays", "retention")}

    def boucle(nom, **kw):
        async def f():
            tours[nom] += 1
        return Boucle(nom, 0.01, f, **kw)

    boucles = [boucle(n, exempte=(n == "retention")) for n in tours]

    async def scenario():
        v = Veille(db, Horloge(), boucles, libre_octets=lambda: libre["v"], seuil_octets=2**30, marge_octets=2**28)
        t = asyncio.create_task(v.executer())
        await asyncio.sleep(0.1)
        assert not v.suspendue and all(n > 0 for n in tours.values())
        libre["v"] = 2**29
        await asyncio.sleep(0.1)
        assert v.suspendue and v.etat()["boucles_suspendues"] == sorted(n for n in tours if n != "retention")
        figes = dict(tours)
        await asyncio.sleep(0.15)
        assert all(tours[n] == figes[n] for n in tours if n != "retention")      # aucune boucle d'écriture
        assert tours["retention"] > figes["retention"]                            # la rétention tourne
        garde = json.loads(db.execute("SELECT valeur FROM executeur_etat WHERE cle = 'garde_espace'").fetchone()[0])
        assert garde["etat"] == "suspendu" and garde["libre_octets"] == 2**29
        libre["v"] = 2**30 + 2**20                                                # > seuil, < seuil + marge : tient
        await asyncio.sleep(0.1)
        assert v.suspendue
        libre["v"] = 2**30 + 2**28 + 1                                            # > seuil + marge : reprise
        await asyncio.sleep(0.12)
        assert not v.suspendue and tours["collecte"] > figes["collecte"]
        garde = json.loads(db.execute("SELECT valeur FROM executeur_etat WHERE cle = 'garde_espace'").fetchone()[0])
        assert garde["etat"] == "ok"
        v.arreter()
        await asyncio.wait_for(t, 2)

    asyncio.run(scenario())


def test_garde_mesure_la_partition_de_veille_db(tmp_path, monkeypatch):
    db = base.ouvrir(tmp_path / "veille.db")
    vus = []
    from veille import service
    monkeypatch.setattr(service.shutil, "disk_usage", lambda p: vus.append(p) or type("U", (), {"free": 5 * 2**30})())
    v = Veille(db, Horloge(), [])
    assert v.verifier_espace() is False
    assert vus == [str(tmp_path)]            # le dossier de la base, pas /var/lib


def test_etat_expose_par_la_route(db):
    from api import reponses
    assert reponses._vue_etat(db)["garde_espace"] == {"etat": "inconnu"}
    db.execute("INSERT INTO executeur_etat VALUES ('garde_espace', ?, ?)", (json.dumps({"etat": "suspendu"}), rfc(0)))
    db.commit()
    assert reponses._vue_etat(db)["garde_espace"] == {"etat": "suspendu"}


def test_service_declare_la_retention_exempte_et_la_migration_0010_existe():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "sbin" / "secubox-ai-veille").read_text(encoding="utf-8")
    assert 'Boucle("retention", 86400, purge, exempte=True)' in src and "retention.liberer" in src
    assert "exempte=True" not in src.replace('Boucle("retention", 86400, purge, exempte=True)', "")   # elle seule

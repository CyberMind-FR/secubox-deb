# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 L2 tâche 6 — stockage des opérations et des sessions de support, côté maître.

Remise « au moins une fois » des notifications (le maître dédoublonne par job), job inconnu accepté, progression avant
l'OPERATE_RESP, fin « résultat inconnu » (rc -1) affichée sans planter, session de support expirée par le maître seul."""
import sqlite3

from pilotage.stockage import StockageSqlite
from outils import GK5, Horloge


def stockage(tmp_path, h=None):
    return StockageSqlite(tmp_path / "p", horloge=h or Horloge())


def test_operation_demandee_puis_acceptee_puis_terminee(tmp_path):
    s = stockage(tmp_path)
    op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    s.operation_reponse(op, "accepte", "a1b2c3d4e5f60718", "")
    assert s.operation_progression(GK5.cle, "a1b2c3d4e5f60718", "en_cours", 50) is True
    fin = s.operation_fin(GK5.cle, "a1b2c3d4e5f60718", 0, "maj-paquets : succès")
    assert fin["id"] == op and fin["action"] == "maj-paquets" and fin["rc"] == 0
    (o,) = s.operations(GK5.cle)
    assert o["etat"] == "termine" and o["resultat"] == "succes" and o["pct"] == 100 and o["acteur"] == "alice"
    assert o["job"] == "a1b2c3d4e5f60718" and o["resume"] == "maj-paquets : succès" and o["fin_le"] is not None


def test_fin_dedoublonnee_par_job(tmp_path):
    s = stockage(tmp_path)
    op = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    s.operation_reponse(op, "accepte", "job1", "")
    assert s.operation_fin(GK5.cle, "job1", 0, "reboot : succès") is not None
    assert s.operation_fin(GK5.cle, "job1", 0, "reboot : succès") is None          # renotification : rien de nouveau
    assert s.operation_fin(GK5.cle, "job1", 1, "reboot : échec (code 1)") is None  # même une fin différente : la première fait foi
    (o,) = s.operations(GK5.cle)
    assert o["rc"] == 0
    # une progression tardive ne fait pas revenir une opération terminée
    assert s.operation_progression(GK5.cle, "job1", "en_cours", 50) is False
    assert s.operations(GK5.cle)[0]["etat"] == "termine"


def test_job_inconnu_et_progression_avant_la_reponse(tmp_path):
    s = stockage(tmp_path)
    # progression d'un job que le maître ne connaît pas encore (l'OPERATE_RESP n'est pas arrivé)
    assert s.operation_progression(GK5.cle, "jobx", "lancee", 0) is True
    (o,) = s.operations(GK5.cle)
    assert o["action"] is None and o["etat"] == "en_cours" and o["etape"] == "lancee"
    op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    fusion = s.operation_reponse(op, "accepte", "jobx", "")
    assert fusion["id"] == op and fusion["etat"] == "en_cours" and fusion["etape"] == "lancee"
    (o,) = s.operations(GK5.cle)      # une seule ligne : l'orpheline a été fusionnée dans la demande
    assert o["action"] == "maj-paquets" and o["job"] == "jobx"


def test_fin_avant_la_reponse_puis_suite_reclamee_une_fois(tmp_path):
    s = stockage(tmp_path)
    fin = s.operation_fin(GK5.cle, "joby", 0, "renommer : succès")
    assert fin["action"] is None
    assert s.operation_reclamer_suite(fin["id"]) is False            # action inconnue : rien à faire encore
    op = s.operation_demander(GK5.cle, "renommer", {"nom": "gk9"}, "alice", None)
    o = s.operation_reponse(op, "accepte", "joby", "")
    assert o["etat"] == "termine" and o["rc"] == 0 and o["args"] == {"nom": "gk9"}
    assert s.operation_reclamer_suite(op) is True
    assert s.operation_reclamer_suite(op) is False                  # une seule fois


def test_job_d_une_autre_box_jamais_melange(tmp_path):
    s = stockage(tmp_path)
    op = s.operation_demander("maillage:gk2", "reboot", {}, "alice", None)
    s.operation_reponse(op, "accepte", "job1", "")
    assert s.operation_fin(GK5.cle, "job1", 0, "x") is not None      # même job, autre box : ligne distincte
    assert s.operations("maillage:gk2")[0]["etat"] == "accepte"


def test_resultat_inconnu_affiche_sans_planter(tmp_path):
    s = stockage(tmp_path)
    op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    s.operation_reponse(op, "accepte", "jobz", "")
    s.operation_fin(GK5.cle, "jobz", -1, "maj-paquets : résultat inconnu")
    o = s.operations(GK5.cle)[0]
    assert o["resultat"] == "inconnu" and o["rc"] == -1
    s.operation_fin(GK5.cle, "jobw", None, "")
    assert s.operations(GK5.cle)[0]["resultat"] == "inconnu"
    op = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    s.operation_reponse(op, "accepte", "jobv", "")
    s.operation_fin(GK5.cle, "jobv", 100, "reboot : échec (code 100)")
    assert s.operations(GK5.cle)[0]["resultat"] == "echec"


def test_consentement_refus_et_sans_reponse(tmp_path):
    s = stockage(tmp_path)
    a = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    s.operation_reponse(a, "consentement", "", "consentement requis")
    b = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    s.operation_sans_reponse(b)
    ops = {o["id"]: o for o in s.operations(GK5.cle)}
    assert ops[a]["etat"] == "consentement" and ops[a]["job"] is None and ops[a]["raison"] == "consentement requis"
    assert ops[b]["etat"] == "sans_reponse" and ops[b]["resultat"] is None


def test_operations_plafonnees_par_box(tmp_path):
    s = StockageSqlite(tmp_path / "p", horloge=Horloge(), operations_max=3)
    ids = [s.operation_demander(GK5.cle, "reboot", {}, "alice", None) for _ in range(5)]
    assert [o["id"] for o in s.operations(GK5.cle)] == list(reversed(ids[-3:]))


def test_migration_depuis_le_schema_de_l1(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    cx = sqlite3.connect(d / "pilotage.db")
    cx.executescript("""
CREATE TABLE boites(cle TEXT PRIMARY KEY, nom TEXT NOT NULL, adresse TEXT NOT NULL, reseau TEXT NOT NULL, client TEXT, abonnement TEXT,
    agent_version TEXT NOT NULL DEFAULT '', vu_le INTEGER NOT NULL, inventaire_le INTEGER, inventaire_partiel INTEGER NOT NULL DEFAULT 0);
CREATE TABLE inventaire(cle TEXT NOT NULL, chemin TEXT NOT NULL, valeur_json TEXT NOT NULL, releve_le INTEGER NOT NULL,
    tronque INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(cle, chemin));
CREATE TABLE evenements(id INTEGER PRIMARY KEY AUTOINCREMENT, cle TEXT NOT NULL, type TEXT NOT NULL, unite TEXT, valeur INTEGER,
    survenu_le INTEGER NOT NULL, recu_le INTEGER NOT NULL);
CREATE TABLE releves(cle TEXT PRIMARY KEY, recu_le INTEGER NOT NULL, duree_s INTEGER NOT NULL, statut TEXT NOT NULL, sortie_json TEXT NOT NULL);
INSERT INTO evenements(cle,type,unite,valeur,survenu_le,recu_le) VALUES('maillage:gk5','X_SECUBOX_Boot',NULL,3,1,1);
""")
    cx.commit()
    cx.close()
    s = StockageSqlite(d, horloge=Horloge())
    (e,) = s.evenements()
    assert e["type"] == "X_SECUBOX_Boot" and e["valeur"] == 3 and e["ident"] is None and e["etat"] is None
    op = s.operation_demander(GK5.cle, "reboot", {}, "alice", None)
    assert s.operations(GK5.cle)[0]["id"] == op
    s.support_demander(GK5.cle, "s1", 30, "alice")
    assert s.supports(GK5.cle)[0]["id"] == "s1"
    StockageSqlite(d, horloge=Horloge())                      # rouvrir une base déjà migrée : sans erreur


def test_notifications_l2_dedoublonnees(tmp_path):
    s = stockage(tmp_path)
    s.vu(GK5, {})
    for _ in range(2):
        s.notification(GK5, {"type": "X_SECUBOX_HandsTied", "etat": "on", "ts": 1})
        s.notification(GK5, {"type": "X_SECUBOX_Consent", "id": "c1", "decision": "accepte", "ts": 2})
    s.notification(GK5, {"type": "X_SECUBOX_HandsTied", "etat": "off", "ts": 3})
    s.notification(GK5, {"type": "X_SECUBOX_HandsTied", "etat": "on", "ts": 4})
    evs = [(e["type"], e["ident"], e["etat"]) for e in reversed(s.evenements())]
    assert evs == [("X_SECUBOX_HandsTied", None, "on"), ("X_SECUBOX_Consent", "c1", "accepte"),
                   ("X_SECUBOX_HandsTied", None, "off"), ("X_SECUBOX_HandsTied", None, "on")]


def test_notifications_d_operation_vont_dans_la_table(tmp_path):
    s = stockage(tmp_path)
    op = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    s.operation_reponse(op, "accepte", "job1", "")
    assert s.notification(GK5, {"type": "X_SECUBOX_OperationProgress", "job": "job1", "etape": "en_cours", "pct": 50, "ts": 1}) is None
    fin = s.notification(GK5, {"type": "X_SECUBOX_OperationDone", "job": "job1", "rc": 0, "resume": "ok", "ts": 2})
    assert fin["id"] == op
    assert s.notification(GK5, {"type": "X_SECUBOX_OperationDone", "job": "job1", "rc": 0, "resume": "ok", "ts": 2}) is None
    assert s.evenements() == []                               # le journal des événements n'est pas pollué par le suivi


def test_support_expire_par_le_maitre_seul(tmp_path):
    h = Horloge()
    s = stockage(tmp_path, h)
    s.support_demander(GK5.cle, "s1", 30, "alice")
    assert s.support_ouvert(GK5.cle, "s1") is None                        # demandé, pas encore accepté sur la box
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s1", "etat": "en_attente", "ts": 1})
    assert s.support_ouvert(GK5.cle, "s1") is None
    fin = "1970-01-12T14:46:40Z"                                          # h.t + 3600 : au-delà de la borne demandée (30 min)
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s1", "etat": "ouvert", "fin": fin, "ts": 2})
    o = s.support_ouvert(GK5.cle, "s1")
    assert o is not None and o["fin"] == int(h.t) + 30 * 60               # la fin est bornée par la durée demandée
    h.avance(29 * 60)
    assert s.support_ouvert(GK5.cle, "s1") is not None
    h.avance(61)                                                          # aucune notification de fermeture : le maître expire seul
    assert s.support_ouvert(GK5.cle, "s1") is None
    assert s.supports(GK5.cle)[0]["etat"] == "expire"


def test_support_fin_de_la_box_plus_courte_et_fermeture(tmp_path):
    h = Horloge()
    s = stockage(tmp_path, h)
    s.support_demander(GK5.cle, "s2", 240, "alice")
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s2", "etat": "ouvert", "fin": "1970-01-12T13:56:40Z", "ts": 1})  # h.t + 600
    assert s.support_ouvert(GK5.cle, "s2")["fin"] == int(h.t) + 600
    assert s.support_ouvert(GK5.cle) is not None                          # n'importe quelle session ouverte de la box
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s2", "etat": "ferme", "ts": 2})
    assert s.support_ouvert(GK5.cle, "s2") is None
    # un « ouvert » renotifié après la fermeture ne rouvre pas la session (état terminal)
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "s2", "etat": "ouvert", "ts": 3})
    assert s.support_ouvert(GK5.cle, "s2") is None


def test_support_ouvert_sans_fin_et_id_inconnu(tmp_path):
    h = Horloge()
    s = stockage(tmp_path, h)
    # session inconnue du maître (jamais demandée par lui) : notée, mais bornée à 4 h au plus, jamais ouverte sans fin
    s.notification(GK5, {"type": "X_SECUBOX_Support", "id": "zz", "etat": "ouvert", "ts": 1})
    assert s.support_ouvert(GK5.cle, "zz")["fin"] == int(h.t) + 240 * 60
    s.support_fermer_local(GK5.cle, "zz")
    assert s.supports(GK5.cle)[0]["etat"] == "ferme"


def test_job_deja_porte_par_une_autre_demande_jamais_fusionne(tmp_path):
    s = stockage(tmp_path)
    a = s.operation_demander(GK5.cle, "maj-paquets", {}, "alice", None)
    s.operation_reponse(a, "accepte", "job1", "")
    b = s.operation_demander(GK5.cle, "maj-paquets", {}, "bob", None)
    o = s.operation_reponse(b, "accepte", "job1", "")          # réponse incohérente : même job qu'une autre demande
    assert o["job"] is None
    ops = {x["id"]: x for x in s.operations(GK5.cle)}
    assert set(ops) == {a, b} and ops[a]["job"] == "job1" and ops[a]["acteur"] == "alice"

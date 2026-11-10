# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3645 — modèle de données MirrorNet v1 : schéma, ledger en partie double, répartition exacte."""
import random
import sqlite3
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secubox_mirrornet import ledger, repartition, schema  # noqa: E402

DID_A, DID_B, DID_C = "did:plc:" + "a" * 32, "did:plc:" + "b" * 32, "did:plc:" + "c" * 32


@pytest.fixture
def cx(tmp_path):
    c = schema.ouvrir(tmp_path / "m.db")
    assert schema.migrer(c) == schema.VERSION
    yield c
    c.close()


# ── schéma ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_migration_idempotente_et_versionnee(tmp_path):
    assert schema.initialiser(tmp_path / "m.db") == 1
    assert schema.initialiser(tmp_path / "m.db") == 1
    c = schema.ouvrir(tmp_path / "m.db")
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    for t in ("node", "offer", "dataset_version", "subscription", "subscription_event", "usage_record", "account",
              "distribution_rule", "ledger_transaction", "ledger_entry", "settlement", "dispute", "trust_policy"):
        assert t in tables, t
    assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_base_plus_recente_que_le_code_jamais_touchee(tmp_path):
    c = schema.ouvrir(tmp_path / "m.db")
    c.execute("PRAGMA user_version = 99")
    with pytest.raises(RuntimeError, match="plus récente"):
        schema.migrer(c)
    assert schema.version(c) == 99


def _noeud(cx, did):
    cx.execute("INSERT INTO node (did, nom) VALUES (?, ?)", (did, did[-4:]))


def _offre(cx, kind="api", classe="public"):
    oid = str(uuid.uuid4())
    cx.execute("INSERT INTO offer (id, ref_annuaire, fournisseur_did, kind, nom, classe, signature, recu_le) "
               "VALUES (?, ?, ?, ?, 'o', ?, 'sig', '2026-11-10T00:00:00Z')", (oid, uuid.uuid4().hex, DID_A, kind, classe))
    return oid


def test_contraintes_du_schema(cx):
    _noeud(cx, DID_A)
    with pytest.raises(sqlite3.IntegrityError):
        cx.execute("INSERT INTO node (did, nom) VALUES ('pas-un-did', 'x')")
    with pytest.raises(sqlite3.IntegrityError):
        _offre(cx, classe="secret")
    with pytest.raises(sqlite3.IntegrityError):         # clé étrangère : fournisseur inconnu
        cx.execute("INSERT INTO offer (id, ref_annuaire, fournisseur_did, kind, nom, signature, recu_le) "
                   "VALUES ('x', 'y', ?, 'api', 'o', 's', 't')", (DID_B,))


def _abonnement(cx):
    _noeud(cx, DID_A)
    _noeud(cx, DID_B)
    oid = _offre(cx)
    sid = str(uuid.uuid4())
    cx.execute("INSERT INTO subscription (id, ref_annuaire, abonne_did, offer_id) VALUES (?, ?, ?, ?)",
               (sid, uuid.uuid4().hex, DID_B, oid))
    return sid


def _releve(cx, sid, seq):
    rid = str(uuid.uuid4())
    cx.execute("INSERT INTO usage_record (id, subscription_id, sequence, periode_debut, periode_fin, unite, quantite, "
               "servi_par, sig_fournisseur, sig_abonne, recu_le) VALUES (?, ?, ?, '2026-11-10T00:00:00Z', "
               "'2026-11-11T00:00:00Z', 'jour', 1, ?, 'sf', 'sa', 't')", (rid, sid, seq, DID_A))
    return rid


def test_releve_d_usage_unique_par_sequence_et_immuable(cx):
    sid = _abonnement(cx)
    rid = _releve(cx, sid, 1)
    with pytest.raises(sqlite3.IntegrityError):         # rejeu : même séquence
        _releve(cx, sid, 1)
    with pytest.raises(sqlite3.IntegrityError, match="immuable"):
        cx.execute("UPDATE usage_record SET quantite = 99 WHERE id = ?", (rid,))
    with pytest.raises(sqlite3.IntegrityError, match="immuable"):
        cx.execute("DELETE FROM usage_record WHERE id = ?", (rid,))


def test_historique_d_abonnement_en_ajout_seul(cx):
    sid = _abonnement(cx)
    cx.execute("INSERT INTO subscription_event (id, subscription_id, vers, ts) VALUES ('e1', ?, 'Actif', 't')", (sid,))
    with pytest.raises(sqlite3.IntegrityError, match="ajout seul"):
        cx.execute("UPDATE subscription_event SET vers = 'Resilie'")
    with pytest.raises(sqlite3.IntegrityError):
        cx.execute("INSERT INTO subscription_event (id, subscription_id, vers, ts) VALUES ('e2', ?, 'Inconnu', 't')", (sid,))


# ── ledger ──────────────────────────────────────────────────────────────────────────────────────────────────────────
def _comptes(cx):
    return (ledger.compte(cx, "credits", DID_B), ledger.compte(cx, "credits", DID_A),
            ledger.compte(cx, "infra", DID_C), ledger.compte(cx, "reserve", "maillage"))


def test_transaction_equilibree_seulement(cx):
    b, a, i, r = _comptes(cx)
    for mauvais in ([(b, -100)], [(b, -100), (a, 90)], [(b, -100), (a, 100.0)], [(b, 0), (a, 0)], [(b, -1), ("?", 1)]):
        with pytest.raises(ledger.LedgerErreur):
            ledger.ecrire_transaction(cx, "x", mauvais)
    assert cx.execute("SELECT COUNT(*) FROM ledger_entry").fetchone()[0] == 0     # rien d'écrit sur un refus
    ledger.ecrire_transaction(cx, "abonnement", [(b, -100), (a, 60), (i, 30), (r, 10)])
    soldes = {(s["nature"], s["titulaire"]): s["solde"] for s in ledger.soldes(cx)}
    assert soldes[("credits", DID_B)] == -100 and soldes[("credits", DID_A)] == 60
    assert ledger.verifier_integrite(cx) == []


def test_idempotence_et_conflit(cx):
    b, a, _, _ = _comptes(cx)
    tx = ledger.ecrire_transaction(cx, "t", [(b, -5), (a, 5)], tx_id="tx-1")
    assert ledger.ecrire_transaction(cx, "t", [(b, -5), (a, 5)], tx_id="tx-1") == tx
    assert cx.execute("SELECT COUNT(*) FROM ledger_entry").fetchone()[0] == 2
    with pytest.raises(ledger.LedgerErreur, match="autre contenu"):
        ledger.ecrire_transaction(cx, "t", [(b, -6), (a, 6)], tx_id="tx-1")


def test_releve_comptabilise_une_seule_fois(cx):
    sid = _abonnement(cx)
    rid = _releve(cx, sid, 1)
    b, a, _, _ = _comptes(cx)
    ledger.ecrire_transaction(cx, "usage", [(b, -10), (a, 10)], usage_record_id=rid)
    with pytest.raises(ledger.LedgerErreur, match="déjà comptabilisé"):
        ledger.ecrire_transaction(cx, "usage bis", [(b, -10), (a, 10)], usage_record_id=rid)


def test_ajout_seul_et_correction_par_inverse(cx):
    b, a, _, _ = _comptes(cx)
    tx = ledger.ecrire_transaction(cx, "t", [(b, -7), (a, 7)])
    with pytest.raises(sqlite3.IntegrityError, match="ajout seul"):
        cx.execute("UPDATE ledger_entry SET montant = 1")
    with pytest.raises(sqlite3.IntegrityError, match="ajout seul"):
        cx.execute("DELETE FROM ledger_entry")
    with pytest.raises(sqlite3.IntegrityError, match="immuable"):
        cx.execute("DELETE FROM ledger_transaction")
    inv = ledger.inverser(cx, tx, "erreur de période")
    assert inv != tx
    with pytest.raises(ledger.LedgerErreur, match="déjà inversée"):
        ledger.inverser(cx, tx, "encore")
    assert all(s["solde"] == 0 for s in ledger.soldes(cx))
    assert ledger.verifier_integrite(cx) == []


def test_alteration_detectee(cx):
    b, a, _, _ = _comptes(cx)
    for n in range(3):
        ledger.ecrire_transaction(cx, f"t{n}", [(b, -(n + 1)), (a, n + 1)])
    # un attaquant qui contourne les déclencheurs (accès direct au fichier) : la chaîne le trahit
    cx.execute("DROP TRIGGER ledger_entry_sans_maj")
    cx.execute("UPDATE ledger_entry SET montant = 999 WHERE rang = 2")
    anomalies = ledger.verifier_integrite(cx)
    assert any("empreinte altérée" in x for x in anomalies) and any("≠ 0" in x for x in anomalies)


def test_regle_versionnee_immuable(cx):
    cx.execute("INSERT INTO distribution_rule (id, version, parts, valide_du, cree_le) "
               "VALUES ('r1', 1, '{\"producteur\":60,\"relais\":15,\"infrastructure\":15,\"reserve\":10}', 't', 't')")
    with pytest.raises(sqlite3.IntegrityError, match="nouvelle version"):
        cx.execute("UPDATE distribution_rule SET parts = '{}'")


# ── répartition ─────────────────────────────────────────────────────────────────────────────────────────────────────
PARTS = {"producteur": 60, "relais": 15, "infrastructure": 15, "reserve": 10}


def test_repartition_exacte_au_centieme():
    rng = random.Random(3645)
    for _ in range(2000):
        m = rng.randint(0, 10_000_000)
        parts = dict(zip(repartition.ROLES, _parts_aleatoires(rng)))
        for avec in (True, False):
            r = repartition.repartir(m, parts, avec_relais=avec)
            assert sum(r.values()) == m and all(v >= 0 for v in r.values())
            if not avec:
                assert r["relais"] == 0


def _parts_aleatoires(rng):
    coupes = sorted(rng.sample(range(1, 100), 3))
    return [coupes[0], coupes[1] - coupes[0], coupes[2] - coupes[1], 100 - coupes[2]]


def test_repartition_exemple_et_sans_relais():
    assert repartition.repartir(100, PARTS) == {"producteur": 60, "relais": 15, "infrastructure": 15, "reserve": 10}
    assert repartition.repartir(100, PARTS, avec_relais=False) == {"producteur": 75, "relais": 0,
                                                                     "infrastructure": 15, "reserve": 10}
    assert sum(repartition.repartir(7, PARTS).values()) == 7


@pytest.mark.parametrize("parts", [{}, {"producteur": 101, "reserve": -1}, {"producteur": 50}, {"inconnu": 100},
                                   {"producteur": 60.0, "relais": 40}, {"producteur": 99, "relais": 1, "x": 0}])
def test_regles_invalides(parts):
    with pytest.raises(repartition.RegleInvalide):
        repartition.valider(parts)


def test_montant_invalide():
    for m in (-1, 1.5, "10"):
        with pytest.raises(repartition.RegleInvalide):
            repartition.repartir(m, PARTS)
    with pytest.raises(repartition.RegleInvalide):
        repartition.repartir(10, PARTS, sans_relais="relais")


# ── relecture de sécurité (#3645) ───────────────────────────────────────────────────────────────────────────────────
def test_insert_or_replace_ne_contourne_pas_l_ajout_seul(cx):
    sid = _abonnement(cx)
    rid = _releve(cx, sid, 1)
    b, a, _, _ = _comptes(cx)
    tx = ledger.ecrire_transaction(cx, "t", [(b, -1), (a, 1)])
    eid = cx.execute("SELECT id, transaction_id, account_id, montant, empreinte_prec, empreinte FROM ledger_entry LIMIT 1").fetchone()
    cx.execute("INSERT INTO subscription_event (id, subscription_id, vers, ts) VALUES ('e1', ?, 'Actif', 't')", (sid,))
    cx.execute("INSERT INTO distribution_rule (id, version, parts, valide_du, cree_le) VALUES ('r1', 1, '{}', 't', 't')")
    for sql, args in (
        ("INSERT OR REPLACE INTO usage_record (id, subscription_id, sequence, periode_debut, periode_fin, unite, quantite, "
         "servi_par, sig_fournisseur, sig_abonne, recu_le) VALUES (?, ?, 1, 'a', 'b', 'jour', 99, 'x', 's', 's', 't')", (rid, sid)),
        ("INSERT OR REPLACE INTO ledger_transaction (id, libelle, ts) VALUES (?, 'faux', 't')", (tx,)),
        ("INSERT OR REPLACE INTO ledger_entry (rang, id, transaction_id, account_id, montant, empreinte_prec, empreinte) "
         "VALUES (1, ?, ?, ?, 999, ?, 'x')", (eid[0], eid[1], eid[2], eid[4])),
        ("INSERT OR REPLACE INTO subscription_event (id, subscription_id, vers, ts) VALUES ('e1', ?, 'Resilie', 't')", (sid,)),
        ("INSERT OR REPLACE INTO distribution_rule (id, version, parts, valide_du, cree_le) VALUES ('r1', 1, '{\"x\":1}', 't', 't')", ()),
    ):
        with pytest.raises(sqlite3.IntegrityError):
            cx.execute(sql, args)
    with pytest.raises(sqlite3.IntegrityError, match="jamais supprimée"):
        cx.execute("DELETE FROM distribution_rule")
    assert ledger.verifier_integrite(cx) == []


def test_inverse_seulement_par_inverser(cx):
    sid = _abonnement(cx)
    rid = _releve(cx, sid, 1)
    b, a, _, _ = _comptes(cx)
    tx = ledger.ecrire_transaction(cx, "usage", [(b, -10), (a, 10)], usage_record_id=rid)
    with pytest.raises(TypeError):                     # plus de porte dérobée inverse_de
        ledger.ecrire_transaction(cx, "x", [(b, -10), (a, 10)], usage_record_id=rid, inverse_de=tx)
    with pytest.raises(ledger.LedgerErreur):           # une « inverse » qui n'est pas l'opposée exacte
        ledger._ecrire(cx, "x", [(b, -10), (a, 10)], tx_id=None, usage_record_id=None, regle_id=None, detail=None,
                       inverse_de=tx)
    with pytest.raises(sqlite3.IntegrityError):        # filet en base : relevé comptabilisé deux fois
        cx.execute("INSERT INTO ledger_transaction (id, usage_record_id, libelle, ts) VALUES ('bis', ?, 'x', 't')", (rid,))
    inv = ledger.inverser(cx, tx, "erreur")
    assert inv == f"inv:{tx}" and ledger.inverser(cx, tx, "erreur") == inv          # rejouer : idempotent
    with pytest.raises(ledger.LedgerErreur):
        ledger.inverser(cx, tx, "autre motif")
    with pytest.raises(sqlite3.IntegrityError):        # filet en base : une seule inverse par transaction
        cx.execute("INSERT INTO ledger_transaction (id, inverse_de, libelle, ts) VALUES ('inv2', ?, 'x', 't')", (tx,))


def test_inversions_concurrentes_une_seule_passe(tmp_path):
    import threading
    base = tmp_path / "m.db"
    schema.initialiser(base)
    cx0 = schema.ouvrir(base)
    b, a = ledger.compte(cx0, "credits", DID_B), ledger.compte(cx0, "credits", DID_A)
    tx = ledger.ecrire_transaction(cx0, "t", [(b, -3), (a, 3)])
    cx0.close()
    res = []

    def inverse(motif):
        c = schema.ouvrir(base)
        try:
            res.append(ledger.inverser(c, tx, motif))
        except (ledger.LedgerErreur, sqlite3.Error) as e:
            res.append(type(e).__name__)
        finally:
            c.close()
    fils = [threading.Thread(target=inverse, args=(f"m{i}",)) for i in range(6)]
    for f in fils:
        f.start()
    for f in fils:
        f.join()
    c = schema.ouvrir(base)
    assert c.execute("SELECT COUNT(*) FROM ledger_transaction WHERE inverse_de = ?", (tx,)).fetchone()[0] == 1
    assert ledger.verifier_integrite(c) == []


def test_alteration_du_contenu_detectee(cx):
    b, a, _, _ = _comptes(cx)
    ledger.ecrire_transaction(cx, "vrai libellé", [(b, -2), (a, 2)])
    cx.execute("DROP TRIGGER ledger_tx_sans_maj")
    cx.execute("UPDATE ledger_transaction SET libelle = 'faux', detail = '{\"x\": 1}'")
    assert any("empreinte altérée" in x for x in ledger.verifier_integrite(cx))
    assert ledger.tete(cx)["rang"] == 2


def test_montants_entiers_meme_en_sql_direct(cx):
    b, a, _, _ = _comptes(cx)
    cx.execute("INSERT INTO ledger_transaction (id, libelle, ts) VALUES ('t', 'x', 't')")
    for m in (1.5, 10 ** 16, -(10 ** 16)):     # un texte numérique (« 12 ») est converti en entier par SQLite : sans risque
        with pytest.raises(sqlite3.IntegrityError):
            cx.execute("INSERT INTO ledger_entry (id, transaction_id, account_id, montant, empreinte_prec, empreinte) "
                       "VALUES (?, 't', ?, ?, 'p', ?)", (str(uuid.uuid4()), b, m, str(uuid.uuid4())))


def test_unite_ledger_prive_et_sans_boucle():
    u = (Path(__file__).resolve().parents[1] / "debian" / "secubox-mirrornet.service").read_text()
    assert "UMask=0077" in u and "StateDirectoryMode=0700" in u and "RestartPreventExitStatus=3" in u
    assert schema.CODE_BASE_TROP_RECENTE == 3

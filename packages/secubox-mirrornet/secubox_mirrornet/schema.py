# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Schéma SQLite de MirrorNet v1 (#3645, docs/MIRRORNET_DATA_MODEL.md).

Une base par nœud, privée : `/var/lib/secubox-mirrornet/mirrornet.db` (WAL). Version du schéma dans
`PRAGMA user_version` ; chaque migration est une liste d'instructions idempotentes appliquée dans UNE transaction.
Le ledger, les événements d'abonnement et les relevés d'usage sont en AJOUT SEUL : des déclencheurs refusent toute
modification ou suppression (une correction est une écriture inverse, jamais une réécriture).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

VERSION = 1

# Identifiants : UUID v4 en texte (36 caractères) pour les objets de ce nœud ; did:plc pour les nœuds ;
# identifiants de l'annuaire (service_id, subscription_id) repris tels quels. Montants : ENTIERS en centièmes de crédit.
MIGRATIONS = {
    1: [
        """CREATE TABLE IF NOT EXISTS node (
            did TEXT PRIMARY KEY CHECK (did GLOB 'did:plc:*'),
            nom TEXT NOT NULL,
            cle_wg TEXT,
            mesh_ip TEXT,
            niveau TEXT NOT NULL DEFAULT 'OBSERVER'
                CHECK (niveau IN ('OBSERVER','LIMITED','PARTNER','TRUSTED','REVOKED')),
            vu_le TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS offer (
            id TEXT PRIMARY KEY,
            ref_annuaire TEXT NOT NULL UNIQUE,
            fournisseur_did TEXT NOT NULL REFERENCES node(did),
            kind TEXT NOT NULL,
            nom TEXT NOT NULL,
            version TEXT,
            classe TEXT NOT NULL DEFAULT 'public'
                CHECK (classe IN ('public','communaute','specialise','professionnel','prive')),
            tarif TEXT NOT NULL DEFAULT '{"modele":"gratuit"}',
            quotas TEXT NOT NULL DEFAULT '{}',
            duree_s INTEGER CHECK (duree_s IS NULL OR duree_s > 0),
            grace_s INTEGER NOT NULL DEFAULT 432000 CHECK (grace_s >= 0),
            etat TEXT NOT NULL DEFAULT 'publiee' CHECK (etat IN ('publiee','retiree')),
            signature TEXT NOT NULL,
            recu_le TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS dataset_version (
            id TEXT PRIMARY KEY,
            offer_id TEXT NOT NULL REFERENCES offer(id),
            numero INTEGER NOT NULL CHECK (numero > 0),
            parent TEXT NOT NULL DEFAULT '',
            empreinte TEXT NOT NULL,
            taille INTEGER NOT NULL CHECK (taille >= 0),
            format TEXT NOT NULL,
            licence TEXT NOT NULL,
            provenance TEXT NOT NULL,
            classe TEXT NOT NULL
                CHECK (classe IN ('public','communaute','specialise','professionnel','prive')),
            fraicheur_s INTEGER CHECK (fraicheur_s IS NULL OR fraicheur_s > 0),
            donnees_personnelles TEXT NOT NULL DEFAULT 'non',
            cree_le TEXT NOT NULL,
            signature TEXT NOT NULL,
            retiree INTEGER NOT NULL DEFAULT 0 CHECK (retiree IN (0,1)),
            UNIQUE (offer_id, numero),
            UNIQUE (offer_id, empreinte)
        )""",
        """CREATE TABLE IF NOT EXISTS subscription (
            id TEXT PRIMARY KEY,
            ref_annuaire TEXT NOT NULL UNIQUE,
            abonne_did TEXT NOT NULL REFERENCES node(did),
            offer_id TEXT NOT NULL REFERENCES offer(id),
            version TEXT,
            tarif_accepte TEXT NOT NULL DEFAULT '{"modele":"gratuit"}',
            renouvellement TEXT NOT NULL DEFAULT 'manuel' CHECK (renouvellement IN ('auto','manuel')),
            expire_le TEXT,
            grace_s INTEGER NOT NULL DEFAULT 432000 CHECK (grace_s >= 0),
            ref_compta TEXT
        )""",
        # Historique des états : la vérité vient du journal de l'annuaire ; cette table en garde la trace locale.
        """CREATE TABLE IF NOT EXISTS subscription_event (
            id TEXT PRIMARY KEY,
            subscription_id TEXT NOT NULL REFERENCES subscription(id),
            de TEXT,
            vers TEXT NOT NULL CHECK (vers IN ('Demande','Refuse','Actif','Grace','Suspendu','Expire','Resilie')),
            acteur_did TEXT,
            motif TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS usage_record (
            id TEXT PRIMARY KEY,
            subscription_id TEXT NOT NULL REFERENCES subscription(id),
            sequence INTEGER NOT NULL CHECK (sequence > 0),
            periode_debut TEXT NOT NULL,
            periode_fin TEXT NOT NULL,
            unite TEXT NOT NULL CHECK (unite IN ('version_recue','requete','octet','jour')),
            quantite INTEGER NOT NULL CHECK (typeof(quantite) = 'integer' AND quantite BETWEEN 0 AND 1000000000000000),
            servi_par TEXT NOT NULL,
            fraicheur_ok INTEGER NOT NULL DEFAULT 1 CHECK (fraicheur_ok IN (0,1)),
            sig_fournisseur TEXT NOT NULL,
            sig_abonne TEXT NOT NULL,
            recu_le TEXT NOT NULL,
            UNIQUE (subscription_id, sequence),
            CHECK (periode_fin > periode_debut)
        )""",
        """CREATE TABLE IF NOT EXISTS account (
            id TEXT PRIMARY KEY,
            nature TEXT NOT NULL CHECK (nature IN ('credits','reserve','infra','en_attente','reglement')),
            titulaire TEXT NOT NULL,
            UNIQUE (nature, titulaire)
        )""",
        """CREATE TABLE IF NOT EXISTS distribution_rule (
            id TEXT PRIMARY KEY,
            version INTEGER NOT NULL UNIQUE CHECK (version > 0),
            parts TEXT NOT NULL,
            sans_relais TEXT NOT NULL DEFAULT 'producteur',
            valide_du TEXT NOT NULL,
            cree_le TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS ledger_transaction (
            id TEXT PRIMARY KEY,
            usage_record_id TEXT REFERENCES usage_record(id),
            regle_id TEXT REFERENCES distribution_rule(id),
            inverse_de TEXT REFERENCES ledger_transaction(id),
            libelle TEXT NOT NULL,
            detail TEXT NOT NULL DEFAULT '{}',
            ts TEXT NOT NULL
        )""",
        # Partie double : Σ(montant) = 0 par transaction, vérifié par ledger.ecrire_transaction et par le contrôle
        # d'intégrité. `empreinte` chaîne chaque écriture à la précédente (rang croissant) : une altération se voit.
        """CREATE TABLE IF NOT EXISTS ledger_entry (
            rang INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            transaction_id TEXT NOT NULL REFERENCES ledger_transaction(id),
            account_id TEXT NOT NULL REFERENCES account(id),
            montant INTEGER NOT NULL
                CHECK (typeof(montant) = 'integer' AND montant <> 0 AND montant BETWEEN -1000000000000000 AND 1000000000000000),
            empreinte_prec TEXT NOT NULL,
            empreinte TEXT NOT NULL UNIQUE
        )""",
        """CREATE TABLE IF NOT EXISTS settlement (
            id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES account(id),
            periode_debut TEXT NOT NULL,
            periode_fin TEXT NOT NULL,
            montant INTEGER NOT NULL
                CHECK (typeof(montant) = 'integer' AND montant BETWEEN -1000000000000000 AND 1000000000000000),
            etat TEXT NOT NULL DEFAULT 'propose' CHECK (etat IN ('propose','accepte','enregistre','annule')),
            reference_externe TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS dispute (
            id TEXT PRIMARY KEY,
            transaction_id TEXT REFERENCES ledger_transaction(id),
            usage_record_id TEXT REFERENCES usage_record(id),
            ouvert_par TEXT NOT NULL,
            motif TEXT NOT NULL,
            etat TEXT NOT NULL DEFAULT 'ouvert' CHECK (etat IN ('ouvert','resolu','rejete')),
            resolution TEXT,
            ouvert_le TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS trust_policy (
            did TEXT PRIMARY KEY REFERENCES node(did),
            niveau TEXT NOT NULL CHECK (niveau IN ('OBSERVER','LIMITED','PARTNER','TRUSTED','REVOKED')),
            cause TEXT NOT NULL,
            maj_le TEXT NOT NULL
        )""",
        # Ajout seul.
        """CREATE TRIGGER IF NOT EXISTS ledger_entry_sans_maj BEFORE UPDATE ON ledger_entry
           BEGIN SELECT RAISE(ABORT, 'ledger en ajout seul : écrire une transaction inverse'); END""",
        """CREATE TRIGGER IF NOT EXISTS ledger_entry_sans_supp BEFORE DELETE ON ledger_entry
           BEGIN SELECT RAISE(ABORT, 'ledger en ajout seul : écrire une transaction inverse'); END""",
        """CREATE TRIGGER IF NOT EXISTS ledger_tx_sans_maj BEFORE UPDATE ON ledger_transaction
           BEGIN SELECT RAISE(ABORT, 'transaction immuable'); END""",
        """CREATE TRIGGER IF NOT EXISTS ledger_tx_sans_supp BEFORE DELETE ON ledger_transaction
           BEGIN SELECT RAISE(ABORT, 'transaction immuable'); END""",
        """CREATE TRIGGER IF NOT EXISTS usage_sans_maj BEFORE UPDATE ON usage_record
           BEGIN SELECT RAISE(ABORT, 'relevé d''usage immuable'); END""",
        """CREATE TRIGGER IF NOT EXISTS usage_sans_supp BEFORE DELETE ON usage_record
           BEGIN SELECT RAISE(ABORT, 'relevé d''usage immuable'); END""",
        """CREATE TRIGGER IF NOT EXISTS evenement_sans_maj BEFORE UPDATE ON subscription_event
           BEGIN SELECT RAISE(ABORT, 'historique en ajout seul'); END""",
        """CREATE TRIGGER IF NOT EXISTS evenement_sans_supp BEFORE DELETE ON subscription_event
           BEGIN SELECT RAISE(ABORT, 'historique en ajout seul'); END""",
        """CREATE TRIGGER IF NOT EXISTS regle_sans_maj BEFORE UPDATE ON distribution_rule
           BEGIN SELECT RAISE(ABORT, 'règle versionnée : publier une nouvelle version'); END""",
        """CREATE TRIGGER IF NOT EXISTS regle_sans_supp BEFORE DELETE ON distribution_rule
           BEGIN SELECT RAISE(ABORT, 'règle versionnée : jamais supprimée'); END""",
        # Un relevé n'est comptabilisé qu'UNE fois (hors inverse) ; une transaction n'est inversée qu'UNE fois.
        """CREATE UNIQUE INDEX IF NOT EXISTS tx_releve_unique ON ledger_transaction(usage_record_id)
           WHERE usage_record_id IS NOT NULL AND inverse_de IS NULL""",
        """CREATE UNIQUE INDEX IF NOT EXISTS tx_inverse_unique ON ledger_transaction(inverse_de)
           WHERE inverse_de IS NOT NULL""",
        "CREATE INDEX IF NOT EXISTS ledger_entry_tx ON ledger_entry(transaction_id)",
        "CREATE INDEX IF NOT EXISTS ledger_entry_compte ON ledger_entry(account_id)",
        "CREATE INDEX IF NOT EXISTS usage_abonnement ON usage_record(subscription_id)",
        "CREATE INDEX IF NOT EXISTS evenement_abonnement ON subscription_event(subscription_id, ts)",
    ],
}


def ouvrir(chemin: Path | str, lecture_seule: bool = False) -> sqlite3.Connection:
    """Connexion avec clés étrangères et WAL. Lecture seule : `mode=ro` (le fichier -shm reste nécessaire en WAL)."""
    if lecture_seule:
        cx = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=5)
    else:
        cx = sqlite3.connect(str(chemin), timeout=5, isolation_level=None)
        cx.execute("PRAGMA journal_mode=WAL")
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA foreign_keys=ON")
    # INSERT OR REPLACE supprime puis insère : sans déclencheurs récursifs, les déclencheurs BEFORE DELETE (ajout seul)
    # ne voient pas cette suppression et un relevé ou une écriture serait remplacé en silence.
    cx.execute("PRAGMA recursive_triggers=ON")
    cx.execute("PRAGMA temp_store=MEMORY")       # tris en mémoire : le profil AppArmor n'ouvre pas /tmp
    return cx


def version(cx: sqlite3.Connection) -> int:
    return int(cx.execute("PRAGMA user_version").fetchone()[0])


def migrer(cx: sqlite3.Connection) -> int:
    """Applique les migrations manquantes, chacune dans UNE transaction ; idempotent. Rend la version atteinte.

    Une base plus récente que ce code (retour arrière du paquet) n'est jamais touchée : erreur explicite."""
    courante = version(cx)
    if courante > VERSION:
        raise RuntimeError(f"base en version {courante}, plus récente que ce code ({VERSION}) : restaurer la sauvegarde "
                           f"ou réinstaller la version du paquet correspondante")
    for v in range(courante + 1, VERSION + 1):
        cx.execute("BEGIN IMMEDIATE")
        try:
            for instruction in MIGRATIONS[v]:
                cx.execute(instruction)
            cx.execute(f"PRAGMA user_version = {int(v)}")
            cx.execute("COMMIT")
        except Exception:
            cx.execute("ROLLBACK")
            raise
    return version(cx)


def initialiser(chemin: Path | str) -> int:
    """Crée ou met à jour la base (appelé au démarrage du service, sous son compte)."""
    cx = ouvrir(chemin)
    try:
        return migrer(cx)
    finally:
        cx.close()


CODE_BASE_TROP_RECENTE = 3     # RestartPreventExitStatus de l'unité : pas de redémarrage en boucle


if __name__ == "__main__":     # ExecStartPre : python3 -m secubox_mirrornet.schema <chemin>
    import sys
    try:
        print(f"mirrornet : schéma en version {initialiser(sys.argv[1] if len(sys.argv) > 1 else '/var/lib/secubox-mirrornet/mirrornet.db')}")
    except RuntimeError as e:
        print(f"mirrornet : {e}", file=sys.stderr)
        sys.exit(CODE_BASE_TROP_RECENTE)

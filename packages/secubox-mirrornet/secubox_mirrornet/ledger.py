# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ledger local en partie double de MirrorNet v1 (#3645, docs/MIRRORNET_ECONOMY.md § 3).

Une transaction = au moins deux écritures entières, non nulles, de somme NULLE, écrites dans UNE transaction SQLite.
Chaque écriture est chaînée à la précédente (BLAKE2b-256) et couvre l'empreinte du CONTENU de sa transaction (libellé,
détail, relevé, règle, inverse, horodatage) ; `verifier_integrite` recalcule chaîne, contenus et sommes. La chaîne n'est
pas clé : sa tête (`tete`) est à ancrer hors de la base (audit, signature du nœud — phase 5) pour détecter une
troncature de queue ou une chaîne entièrement recalculée.
Idempotence : réécrire une transaction de même identifiant et de même contenu ne fait rien ; un contenu différent sous le
même identifiant est refusé. Une correction passe par `inverser` seulement. Rien n'est jamais modifié ni supprimé.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

GENESE = "0" * 64
NATURES = ("credits", "reserve", "infra", "en_attente", "reglement")


class LedgerErreur(ValueError):
    """Transaction refusée : rien n'a été écrit."""


def _maintenant() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _empreinte(prec: str, entree_id: str, tx_id: str, tx_emp: str, compte: str, montant: int) -> str:
    brut = "\x1f".join((prec, entree_id, tx_id, tx_emp, compte, str(montant))).encode()
    return hashlib.blake2b(brut, digest_size=32).hexdigest()


def _empreinte_tx(tx_id: str, libelle: str, detail: str, usage_record_id, regle_id, inverse_de, ts: str) -> str:
    brut = json.dumps([tx_id, libelle, detail, usage_record_id, regle_id, inverse_de, ts], ensure_ascii=False)
    return hashlib.blake2b(brut.encode(), digest_size=32).hexdigest()


def compte(cx: sqlite3.Connection, nature: str, titulaire: str) -> str:
    """Identifiant du compte (nature, titulaire), créé au besoin."""
    if nature not in NATURES or not titulaire:
        raise LedgerErreur(f"compte invalide : {nature!r} / {titulaire!r}")
    ligne = cx.execute("SELECT id FROM account WHERE nature = ? AND titulaire = ?", (nature, titulaire)).fetchone()
    if ligne:
        return ligne[0]
    cid = str(uuid.uuid4())
    cx.execute("INSERT OR IGNORE INTO account (id, nature, titulaire) VALUES (?, ?, ?)", (cid, nature, titulaire))
    return cx.execute("SELECT id FROM account WHERE nature = ? AND titulaire = ?", (nature, titulaire)).fetchone()[0]


def _valider(ecritures: List[Tuple[str, int]]) -> None:
    if len(ecritures) < 2:
        raise LedgerErreur("une transaction a au moins deux écritures")
    for c, m in ecritures:
        if not isinstance(c, str) or not c:
            raise LedgerErreur("compte manquant")
        if type(m) is not int or m == 0:
            raise LedgerErreur("montant entier non nul exigé (centièmes de crédit)")
    if sum(m for _, m in ecritures) != 0:
        raise LedgerErreur("partie double : la somme des écritures doit être nulle")


def ecrire_transaction(cx: sqlite3.Connection, libelle: str, ecritures: Iterable[Tuple[str, int]], *,
                       tx_id: Optional[str] = None, usage_record_id: Optional[str] = None,
                       regle_id: Optional[str] = None, detail: Optional[Dict] = None) -> str:
    """Écrit une transaction équilibrée et rend son identifiant. `ecritures` : [(account_id, montant), …].
    Une correction ne passe jamais par ici : `inverser`."""
    return _ecrire(cx, libelle, ecritures, tx_id=tx_id, usage_record_id=usage_record_id, regle_id=regle_id,
                   detail=detail, inverse_de=None)


def _ecrire(cx: sqlite3.Connection, libelle: str, ecritures: Iterable[Tuple[str, int]], *, tx_id: Optional[str],
            usage_record_id: Optional[str], regle_id: Optional[str], detail: Optional[Dict],
            inverse_de: Optional[str]) -> str:
    ecr = [(c, m) for c, m in ecritures]
    _valider(ecr)
    tx_id = tx_id or str(uuid.uuid4())
    detail_json = json.dumps(detail or {}, sort_keys=True, ensure_ascii=False)
    cx.execute("BEGIN IMMEDIATE")
    try:
        existante = cx.execute("SELECT libelle, usage_record_id, regle_id, inverse_de, detail FROM ledger_transaction "
                               "WHERE id = ?", (tx_id,)).fetchone()
        if existante is not None:
            deja = sorted((r[0], r[1]) for r in cx.execute(
                "SELECT account_id, montant FROM ledger_entry WHERE transaction_id = ?", (tx_id,)))
            if (tuple(existante) == (libelle, usage_record_id, regle_id, inverse_de, detail_json)
                    and deja == sorted(ecr)):
                cx.execute("ROLLBACK")
                return tx_id                      # idempotent : déjà écrite à l'identique
            if inverse_de is not None:
                raise LedgerErreur(f"transaction {inverse_de} déjà inversée (autre motif)")
            raise LedgerErreur(f"transaction {tx_id} déjà écrite avec un autre contenu")
        for c, _ in ecr:
            if cx.execute("SELECT 1 FROM account WHERE id = ?", (c,)).fetchone() is None:
                raise LedgerErreur(f"compte inconnu : {c}")
        if inverse_de is not None:
            # dans la MÊME transaction SQLite que l'écriture : deux inversions concurrentes ne passent jamais toutes deux
            originale = sorted((r[0], -r[1]) for r in cx.execute(
                "SELECT account_id, montant FROM ledger_entry WHERE transaction_id = ?", (inverse_de,)))
            if not originale:
                raise LedgerErreur(f"transaction inconnue : {inverse_de}")
            if cx.execute("SELECT 1 FROM ledger_transaction WHERE inverse_de = ?", (inverse_de,)).fetchone():
                raise LedgerErreur(f"transaction {inverse_de} déjà inversée")
            if sorted(ecr) != originale:
                raise LedgerErreur("une inverse reprend exactement les écritures opposées de l'originale")
        elif usage_record_id and cx.execute(
                "SELECT 1 FROM ledger_transaction WHERE usage_record_id = ? AND inverse_de IS NULL",
                (usage_record_id,)).fetchone():
            raise LedgerErreur("ce relevé d'usage est déjà comptabilisé")
        ts = _maintenant()
        cx.execute("INSERT INTO ledger_transaction (id, usage_record_id, regle_id, inverse_de, libelle, detail, ts) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (tx_id, usage_record_id, regle_id, inverse_de, libelle, detail_json, ts))
        tx_emp = _empreinte_tx(tx_id, libelle, detail_json, usage_record_id, regle_id, inverse_de, ts)
        ligne = cx.execute("SELECT empreinte FROM ledger_entry ORDER BY rang DESC LIMIT 1").fetchone()
        prec = ligne[0] if ligne else GENESE
        for c, m in ecr:
            eid = str(uuid.uuid4())
            emp = _empreinte(prec, eid, tx_id, tx_emp, c, m)
            cx.execute("INSERT INTO ledger_entry (id, transaction_id, account_id, montant, empreinte_prec, empreinte) "
                       "VALUES (?, ?, ?, ?, ?, ?)", (eid, tx_id, c, m, prec, emp))
            prec = emp
        cx.execute("COMMIT")
    except Exception:
        if cx.in_transaction:
            cx.execute("ROLLBACK")
        raise
    return tx_id


def inverser(cx: sqlite3.Connection, tx_id: str, motif: str) -> str:
    """Correction : transaction inverse (montants opposés) liée à l'originale, qui reste intacte. Identifiant
    déterministe (`inv:<tx>`) : rejouer la même correction ne fait rien ; une seconde correction différente est refusée.
    Un relevé inversé n'est plus recomptabilisable : la correction d'usage passe par un nouveau relevé."""
    ecr = [(r[0], -r[1]) for r in cx.execute(
        "SELECT account_id, montant FROM ledger_entry WHERE transaction_id = ? ORDER BY rang", (tx_id,))]
    if not ecr:
        raise LedgerErreur(f"transaction inconnue : {tx_id}")
    return _ecrire(cx, f"inverse : {motif}", ecr, tx_id=f"inv:{tx_id}", usage_record_id=None, regle_id=None,
                   detail={"motif": motif}, inverse_de=tx_id)


def tete(cx: sqlite3.Connection) -> Dict:
    """Tête de chaîne (rang, empreinte) : à ancrer hors de la base (phase 5)."""
    ligne = cx.execute("SELECT rang, empreinte FROM ledger_entry ORDER BY rang DESC LIMIT 1").fetchone()
    return {"rang": ligne[0], "empreinte": ligne[1]} if ligne else {"rang": 0, "empreinte": GENESE}


def soldes(cx: sqlite3.Connection) -> List[Dict]:
    return [dict(nature=r[0], titulaire=r[1], solde=r[2]) for r in cx.execute(
        "SELECT a.nature, a.titulaire, COALESCE(SUM(e.montant), 0) FROM account a "
        "LEFT JOIN ledger_entry e ON e.account_id = a.id GROUP BY a.id ORDER BY a.nature, a.titulaire")]


def verifier_integrite(cx: sqlite3.Connection) -> List[str]:
    """Anomalies du ledger (liste vide = intègre) : chaîne rompue ou altérée (écriture OU contenu de sa transaction),
    écriture orpheline, transaction déséquilibrée ou incomplète. Ne détecte pas seule une troncature de queue : comparer
    `tete` à son ancrage."""
    anomalies: List[str] = []
    txs = {r[0]: _empreinte_tx(*r) for r in cx.execute(
        "SELECT id, libelle, detail, usage_record_id, regle_id, inverse_de, ts FROM ledger_transaction")}
    prec = GENESE
    for rang, eid, tx, compte_id, montant, e_prec, emp in cx.execute(
            "SELECT rang, id, transaction_id, account_id, montant, empreinte_prec, empreinte FROM ledger_entry ORDER BY rang"):
        if e_prec != prec:
            anomalies.append(f"écriture {rang} : chaîne rompue (précédente attendue {prec[:12]}…)")
        if tx not in txs:
            anomalies.append(f"écriture {rang} : transaction {tx} absente")
        elif emp != _empreinte(e_prec, eid, tx, txs[tx], compte_id, montant):
            anomalies.append(f"écriture {rang} : empreinte altérée (écriture ou contenu de sa transaction)")
        prec = emp
    for tx, n, somme in cx.execute(
            "SELECT t.id, COUNT(e.id), COALESCE(SUM(e.montant), 0) FROM ledger_transaction t "
            "LEFT JOIN ledger_entry e ON e.transaction_id = t.id GROUP BY t.id"):
        if n < 2:
            anomalies.append(f"transaction {tx} : {n} écriture(s)")
        if somme != 0:
            anomalies.append(f"transaction {tx} : somme {somme} ≠ 0")
    return anomalies

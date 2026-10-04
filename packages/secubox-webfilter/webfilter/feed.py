# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Boucle d'alimentation : lignes du journal d'Unbound → événements classés → compteurs. Testable sans Unbound (itérateur de lignes)."""
import dataclasses
import json
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from . import analyse, listes


class Reunion:
    """Plusieurs index d'une même catégorie (une source par liste) : un nom est classé s'il figure dans l'un d'eux."""

    def __init__(self, indexes):
        self._i = list(indexes)

    def correspondance(self, nom: str) -> str | None:
        for i in self._i:
            e = i.correspondance(nom)
            if e:
                return e
        return None

    def contient(self, nom: str) -> bool:
        return self.correspondance(nom) is not None


def charger_indexes(dossier, categories) -> dict:
    """{catégorie: Reunion} d'après `dossier/<catégorie>/<source>.idx`. Un index illisible est ignoré et signalé ; une catégorie sans aucun
    index lisible est absente."""
    sortie = {}
    for cat in categories:
        trouves = []
        for s in cat.sources:
            f = Path(dossier) / cat.id / f"{s.nom}.idx"
            if not f.is_file():
                continue
            try:
                trouves.append(listes.Index.charger(f))
            except (ValueError, OSError) as e:
                print(f"secubox-webfilter : index {cat.id}/{s.nom} ignoré : {e}", file=sys.stderr)
        if trouves:
            sortie[cat.id] = Reunion(trouves)
    return sortie


def adresses_locales() -> set:
    """Les adresses de la box elle-même (ses propres requêtes ne sont pas comptées)."""
    try:
        r = subprocess.run(["/usr/sbin/ip", "-j", "addr"], capture_output=True, text=True, timeout=10, check=False)
        return {a["local"] for i in json.loads(r.stdout or "[]") for a in i.get("addr_info", []) if "local" in a}
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        print(f"secubox-webfilter : adresses locales illisibles : {e}", file=sys.stderr)
        return set()


def suivre(lignes, mag, indexes_fn, exclus_fn, periode_s: float = 2.0, lot: int = 200, recharge_s: float = 60.0,
           retention_jours: int | None = None, purge_s: float = 3600.0, horloge=time.monotonic) -> int:
    """Consomme `lignes` ; rend le nombre d'événements classés et enregistrés. Une ligne hostile est ignorée ; une erreur d'écriture est
    signalée et le lot perdu, jamais le démon."""
    indexes, exclus = indexes_fn(), exclus_fn()
    t_flush = t_recharge = t_purge = horloge()
    if retention_jours:
        mag.purger(retention_jours)
    attente, total = [], 0

    def vider():
        nonlocal attente, total
        if attente:
            try:
                total += mag.ajouter(attente, exclus)
            except sqlite3.Error as e:
                print(f"secubox-webfilter : écriture des compteurs impossible : {e}", file=sys.stderr)
            attente = []

    for texte in lignes:
        e = analyse.ligne(texte)
        now = horloge()
        if now - t_recharge >= recharge_s:
            indexes, exclus, t_recharge = indexes_fn(), exclus_fn(), now
        if e is not None:
            r = analyse.classer(e.qname, indexes)
            if r:
                cat, entree = r
                attente.append((dataclasses.replace(e, qname=entree), cat))       # on compte l'ENTRÉE de liste, pas le nom interrogé
        if len(attente) >= lot or (attente and now - t_flush >= periode_s):
            vider()
            t_flush = now
        if retention_jours and now - t_purge >= purge_s:
            try:
                mag.purger(retention_jours)
            except sqlite3.Error as err:
                print(f"secubox-webfilter : purge impossible : {err}", file=sys.stderr)
            t_purge = now
    vider()
    return total

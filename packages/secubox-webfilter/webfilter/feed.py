# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Boucle d'alimentation : lignes du journal d'Unbound → événements classés → compteurs. Testable sans Unbound (itérateur de lignes)."""
import contextlib
import dataclasses
import ipaddress
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
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


MAX_CARTE = 1024 * 1024
MAX_CONNUS = 512
MAX_VUS = 4096


def lire_carte(chemin) -> dict:
    """`carte.json` écrite par le contrôleur root : tolérante (absente, énorme, illisible → {}), jamais d'exception."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(MAX_CARTE + 1)
        if len(brut) > MAX_CARTE:
            return {}
        d = json.loads(brut.decode("utf-8"))
    except (OSError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def decision(carte, client: str, cat: str) -> str:
    """« bloque » si, pour cette adresse, la catégorie est en mode block (appareil assigné, sinon profil par défaut du réseau) ; « observe » sinon,
    et dans tous les cas douteux : une carte illisible ne fait jamais compter « bloqué »."""
    try:
        a = carte["adresses"].get(client)
        if a is not None:
            return "bloque" if a["modes"].get(cat) == "block" else "observe"
        d = carte.get("defaut")
        if d and any(ipaddress.ip_address(client) in ipaddress.ip_network(n) for n in d["reseaux"]):
            return "bloque" if d["modes"].get(cat) == "block" else "observe"
    except (AttributeError, KeyError, TypeError, ValueError):
        pass
    return "observe"


def publier_connus(chemin, voisins: dict, vus: set, maintenant=time.time) -> None:
    """`connus.json` : les appareils (MAC) dont une adresse a été VUE dans le journal, avec ces seules adresses ; 512 au plus. Aucune adresse devinée."""
    sortie = {}
    for mac in sorted(voisins):
        adr = [a for a in voisins[mac] if a in vus]
        if adr:
            sortie[mac] = {"adresses": adr, "vu": int(maintenant())}
        if len(sortie) >= MAX_CONNUS:
            break
    chemin = Path(chemin)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".connus-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sortie, f)
            f.flush()
            os.fchmod(f.fileno(), 0o640)
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def suivre(lignes, mag, indexes_fn, exclus_fn, periode_s: float = 2.0, lot: int = 200, recharge_s: float = 60.0,
           retention_jours: int | None = None, purge_s: float = 3600.0, horloge=time.monotonic, carte_fn=None, connus_fn=None,
           connus_s: float = 300.0) -> int:
    """Consomme `lignes` ; rend le nombre d'événements classés et enregistrés. Une ligne hostile est ignorée ; une erreur d'écriture est
    signalée et le lot perdu, jamais le démon."""
    indexes, exclus = indexes_fn(), exclus_fn()
    carte = carte_fn() if carte_fn else {}
    vus: set = set()
    t_flush = t_recharge = t_purge = t_connus = horloge()
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
            if carte_fn:
                carte = carte_fn()
        if e is not None:
            if len(vus) < MAX_VUS:
                vus.add(e.client)
            r = analyse.classer(e.qname, indexes)
            if r:
                cat, entree = r
                attente.append((dataclasses.replace(e, qname=entree), cat, decision(carte, e.client, cat)))     # l'ENTRÉE de liste, pas le nom interrogé
        if connus_fn and now - t_connus >= connus_s:
            try:
                connus_fn(vus)
            except OSError as err:
                print(f"secubox-webfilter : appareils connus non publiés : {err}", file=sys.stderr)
            vus, t_connus = set(), now
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

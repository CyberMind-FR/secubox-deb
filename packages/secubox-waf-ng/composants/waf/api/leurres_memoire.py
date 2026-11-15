# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: WAF :: mémoire des leurres de service (#3734)

sbx-authwatch écrit une ligne `leurre:<service>` par connexion à un leurre dans le journal des menaces (#3728) :
adresse, profil (balayeur, sondeur, force-brute), client, identifiants tentés EN CLAIR (décision du propriétaire :
aucun service ni compte derrière ces ports). Le journal tourne en 7 jours ; cette mémoire en garde 30 dans une base
SQLite et répond aux questions que le journal ne sait pas poser : qui revient, avec quel dictionnaire, quel mot de
passe est rejoué sur plusieurs comptes ou depuis plusieurs adresses.

Ingestion à curseur (inode, octet) : chaque appel ne lit que la fin du journal ; à la rotation, le reste de l'ancien
fichier (`.1`) est lu avant de reprendre au début du nouveau. Seules les lignes complètes sont consommées.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

FENETRE_S = 30 * 86400
CLIENT_MAX = 200
CHAMP_MAX = 128
ESSAIS_MAX = 10            # par visite (authwatch en envoie 5 au plus)
LECTURE_MAX = 64 << 20     # octets lus par appel : un journal entier (20 Mo à la rotation) passe en une fois
PROFILS = {"balayeur": 0, "sondeur": 1, "force-brute": 2}
_NOMS_PROFIL = {v: k for k, v in PROFILS.items()}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS visites(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, ip TEXT NOT NULL, service TEXT NOT NULL,
  profil INTEGER NOT NULL, client TEXT NOT NULL, action TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS visites_ip ON visites(ip, ts);
CREATE INDEX IF NOT EXISTS visites_ts ON visites(ts);
CREATE TABLE IF NOT EXISTS essais(
  visite INTEGER NOT NULL REFERENCES visites(id) ON DELETE CASCADE, rang INTEGER NOT NULL,
  compte TEXT NOT NULL, mdp TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS essais_visite ON essais(visite);
CREATE INDEX IF NOT EXISTS essais_mdp ON essais(mdp);
CREATE TABLE IF NOT EXISTS curseur(id INTEGER PRIMARY KEY CHECK (id = 1), inode INTEGER NOT NULL, octet INTEGER NOT NULL);
"""


def _instant(e: dict, defaut: int) -> int:
    if isinstance(e.get("at"), int) and e["at"] > 0:
        return e["at"]
    try:
        return int(datetime.fromisoformat(str(e.get("timestamp"))).timestamp())
    except ValueError:
        return defaut


def _bloc(ip: str) -> str:
    return ip.rsplit(".", 1)[0] if "." in ip else ip


class Memoire:
    def __init__(self, chemin: Path, journal: Path):
        self.chemin = Path(chemin)
        self.journal = Path(journal)
        self._verrou = threading.Lock()

    # ── base ────────────────────────────────────────────────────────────
    def _ouvrir(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.chemin, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        c.executescript(_SCHEMA)
        # Ouverte au GROUPE secubox-waf quel que soit l'umask : secubox-waf-ng.service fait `chown -R secubox-waf` sur
        # ce répertoire à chaque démarrage (même piège que ai-ban.jsonl, #3716).
        try:
            st = os.stat(self.chemin)
            if st.st_uid == os.geteuid() and st.st_mode & 0o777 != 0o660:
                os.chmod(self.chemin, 0o660)
        except OSError:
            pass
        return c

    # ── ingestion ───────────────────────────────────────────────────────
    def _lire_depuis(self, chemin: Path, octet: int) -> tuple:
        """(lignes complètes, octet après la dernière ligne complète)."""
        try:
            with open(chemin, "rb") as f:
                f.seek(octet)
                brut = f.read(LECTURE_MAX)
        except OSError:
            return [], octet
        fin = brut.rfind(b"\n") + 1
        return brut[:fin].splitlines(), octet + fin

    def _inserer(self, c: sqlite3.Connection, lignes: List[bytes], maintenant: int) -> int:
        n = 0
        for brut in lignes:
            if b'"leurre:' not in brut:
                continue
            try:
                e = json.loads(brut)
            except ValueError:
                continue
            cat = e.get("category") if isinstance(e, dict) else None
            if not isinstance(cat, str) or not cat.startswith("leurre:") or not e.get("client_ip"):
                continue
            cur = c.execute(
                "INSERT INTO visites(ts, ip, service, profil, client, action) VALUES (?,?,?,?,?,?)",
                (_instant(e, maintenant), str(e["client_ip"])[:64], cat[7:][:32],
                 PROFILS.get(str(e.get("agent")), 0), str(e.get("user_agent") or "")[:CLIENT_MAX],
                 str(e.get("action") or "")[:16]))
            essais = e.get("essais") if isinstance(e.get("essais"), list) else []
            for rang, x in enumerate(essais[:ESSAIS_MAX]):
                if isinstance(x, dict):
                    c.execute("INSERT INTO essais(visite, rang, compte, mdp) VALUES (?,?,?,?)",
                              (cur.lastrowid, rang, str(x.get("compte") or "")[:CHAMP_MAX],
                               str(x.get("mot_de_passe") or "")[:CHAMP_MAX]))
            n += 1
        return n

    def ingerer(self, maintenant: int) -> int:
        """Lit la suite du journal ; rend le nombre de visites ajoutées. Ne lève pas si le journal est absent."""
        with self._verrou, self._ouvrir() as c:
            r = c.execute("SELECT inode, octet FROM curseur WHERE id = 1").fetchone()
            inode, octet = (r["inode"], r["octet"]) if r else (0, 0)
            try:
                st = os.stat(self.journal)
            except OSError:
                return 0
            n = 0
            if inode and st.st_ino != inode:
                # Rotation par renommage : finir l'ancien fichier s'il est encore là (`.1`, non compressé un jour).
                ancien = Path(str(self.journal) + ".1")
                try:
                    if os.stat(ancien).st_ino == inode:
                        lignes, _ = self._lire_depuis(ancien, octet)
                        n += self._inserer(c, lignes, maintenant)
                except OSError:
                    pass
                octet = 0
            elif st.st_size < octet:
                octet = 0                      # tronqué sur place
            lignes, octet = self._lire_depuis(self.journal, octet)
            n += self._inserer(c, lignes, maintenant)
            c.execute("INSERT INTO curseur(id, inode, octet) VALUES (1, ?, ?) "
                      "ON CONFLICT(id) DO UPDATE SET inode = excluded.inode, octet = excluded.octet",
                      (st.st_ino, octet))
            return n

    def purger(self, maintenant: int) -> int:
        with self._verrou, self._ouvrir() as c:
            return c.execute("DELETE FROM visites WHERE ts < ?", (maintenant - FENETRE_S,)).rowcount

    # ── lectures ────────────────────────────────────────────────────────
    def _lire(self, sql: str, args: tuple = ()) -> List[sqlite3.Row]:
        with self._verrou, self._ouvrir() as c:
            return c.execute(sql, args).fetchall()

    def _couples(self, depuis: int) -> List[sqlite3.Row]:
        """Tous les essais de la fenêtre, avec leur visite, dans l'ordre où ils ont été tentés."""
        return self._lire(
            "SELECT v.id, v.ip, v.service, v.client, e.compte, e.mdp FROM essais e JOIN visites v ON v.id = e.visite "
            "WHERE v.ts >= ? ORDER BY v.ts, v.id, e.rang", (depuis,))

    def attaquants(self, maintenant: int, filtre: str = "", profil: str = "", limite: int = 200) -> List[dict]:
        depuis = maintenant - FENETRE_S
        par_ip: Dict[str, dict] = {}
        for v in self._lire("SELECT ip, service, profil, client, ts FROM visites WHERE ts >= ? ORDER BY ts, id",
                            (depuis,)):
            a = par_ip.setdefault(v["ip"], {"ip": v["ip"], "services": set(), "profil": 0, "client": "",
                                             "clients": set(), "visites": 0, "premiere": v["ts"], "derniere": v["ts"],
                                             "essais": [], "_mdp": {}})
            a["services"].add(v["service"])
            a["profil"] = max(a["profil"], v["profil"])
            a["visites"] += 1
            a["derniere"] = v["ts"]
            if v["client"]:
                a["client"] = v["client"]
                a["clients"].add(v["client"])
        for e in self._couples(depuis):
            a = par_ip[e["ip"]]
            couple = {"compte": e["compte"], "mot_de_passe": e["mdp"]}
            if couple not in a["essais"]:
                a["essais"].append(couple)
            if e["mdp"] and e["compte"]:
                a["_mdp"].setdefault(e["mdp"], set()).add(e["compte"])
        f = filtre.strip().lower()
        sortie = []
        for a in sorted(par_ip.values(), key=lambda x: -x["derniere"]):
            nom = _NOMS_PROFIL[a["profil"]]
            if profil and profil != nom:
                continue
            if f and not (f in a["ip"].lower() or any(f in c.lower() for c in a["clients"])
                          or any(f in x["compte"].lower() or f in x["mot_de_passe"].lower() for x in a["essais"])):
                continue
            sortie.append({"ip": a["ip"], "services": sorted(a["services"]), "profil": nom, "client": a["client"],
                           "visites": a["visites"], "premiere": a["premiere"], "derniere": a["derniere"],
                           "nb_essais": len(a["essais"]), "essais": a["essais"][:5],
                           "rejeu": any(len(c) > 1 for c in a["_mdp"].values())})
            if len(sortie) >= limite:
                break
        return sortie

    def fiche(self, ip: str, maintenant: int) -> dict:
        visites = [dict(id=v["id"], ts=v["ts"], service=v["service"], profil=_NOMS_PROFIL[v["profil"]],
                        client=v["client"], action=v["action"], essais=[])
                   for v in self._lire("SELECT * FROM visites WHERE ip = ? AND ts >= ? ORDER BY ts DESC, id DESC "
                                       "LIMIT 500", (ip, maintenant - FENETRE_S))]
        par_id = {v["id"]: v for v in visites}
        if par_id:
            for e in self._lire("SELECT visite, compte, mdp FROM essais WHERE visite IN (%s) ORDER BY visite, rang"
                                % ",".join("?" * len(par_id)), tuple(par_id)):
                par_id[e["visite"]]["essais"].append({"compte": e["compte"], "mot_de_passe": e["mdp"]})
        for v in visites:
            del v["id"]
        return {"ip": ip, "visites": visites}

    def dictionnaire(self, maintenant: int, limite: int = 50) -> dict:
        mdp: Dict[str, dict] = {}
        comptes: Dict[str, dict] = {}
        couples = set()
        for e in self._couples(maintenant - FENETRE_S):
            couples.add((e["compte"], e["mdp"]))
            m = mdp.setdefault(e["mdp"], {"comptes": set(), "adresses": set(), "essais": 0})
            m["essais"] += 1
            m["adresses"].add(e["ip"])
            if e["compte"]:
                m["comptes"].add(e["compte"])
                c = comptes.setdefault(e["compte"], {"adresses": set(), "essais": 0})
                c["essais"] += 1
                c["adresses"].add(e["ip"])
        return {
            "couples": len(couples),
            "mots_de_passe": [{"mot_de_passe": k, "comptes": len(v["comptes"]), "adresses": len(v["adresses"]),
                               "essais": v["essais"]}
                              for k, v in sorted(mdp.items(), key=lambda kv: (-kv[1]["essais"], kv[0]))[:limite]],
            "comptes": [{"compte": k, "adresses": len(v["adresses"]), "essais": v["essais"]}
                        for k, v in sorted(comptes.items(), key=lambda kv: (-kv[1]["essais"], kv[0]))[:limite]],
        }

    def rejeux(self, maintenant: int, limite: int = 30) -> dict:
        depuis = maintenant - FENETRE_S
        mdp: Dict[str, dict] = {}
        couple: Dict[tuple, set] = {}
        for e in self._couples(depuis):
            if e["ip"] == "local":
                continue
            if e["mdp"]:
                m = mdp.setdefault(e["mdp"], {"comptes": set(), "adresses": set()})
                m["adresses"].add(e["ip"])
                if e["compte"]:
                    m["comptes"].add(e["compte"])
            if e["compte"] or e["mdp"]:
                couple.setdefault((e["compte"], e["mdp"]), set()).add(e["ip"])
        client: Dict[str, dict] = {}
        for v in self._lire("SELECT DISTINCT client, service, ip FROM visites WHERE ts >= ? AND client != '' "
                            "AND ip != 'local'", (depuis,)):
            c = client.setdefault(v["client"], {"services": set(), "adresses": set()})
            c["services"].add(v["service"])
            c["adresses"].add(v["ip"])
        return {
            "mot_de_passe_plusieurs_comptes": [
                {"mot_de_passe": k, "comptes": sorted(v["comptes"])[:20], "adresses": len(v["adresses"])}
                for k, v in sorted(mdp.items(), key=lambda kv: (-len(kv[1]["comptes"]), kv[0]))
                if len(v["comptes"]) > 1][:limite],
            "couple_plusieurs_adresses": [
                {"compte": k[0], "mot_de_passe": k[1], "adresses": sorted(v)[:200],
                 "blocs": len({_bloc(ip) for ip in v})}
                for k, v in sorted(couple.items(), key=lambda kv: (-len(kv[1]), kv[0])) if len(v) > 1][:limite],
            "client_plusieurs_leurres": [
                {"client": k, "services": sorted(v["services"]), "adresses": len(v["adresses"])}
                for k, v in sorted(client.items(), key=lambda kv: (-len(kv[1]["services"]), kv[0]))
                if len(v["services"]) > 1][:limite],
        }

    def resume(self, maintenant: int) -> dict:
        depuis = maintenant - FENETRE_S
        par_leurre = {r["service"]: r["n"] for r in self._lire(
            "SELECT service, COUNT(*) AS n FROM visites WHERE ts >= ? GROUP BY service", (depuis,))}
        r = self._lire("SELECT COUNT(DISTINCT ip) AS a, MIN(ts) AS p FROM visites WHERE ts >= ? AND ip != 'local'",
                       (depuis,))[0]
        premiere: Optional[int] = self._lire("SELECT MIN(ts) AS p FROM visites WHERE ts >= ?", (depuis,))[0]["p"]
        rj = self.rejeux(maintenant, limite=10_000)
        return {"attaquants": r["a"], "touches": sum(par_leurre.values()),
                "couples": self.dictionnaire(maintenant, limite=0)["couples"],
                "rejeux": sum(len(v) for v in rj.values()), "par_leurre": par_leurre, "premiere": premiere,
                "fenetre_jours": FENETRE_S // 86400}

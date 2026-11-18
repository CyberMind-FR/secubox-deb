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

import contextlib
import json
import logging
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
TRANCHE = 4 << 20          # octets lus par tranche ; l'ingestion boucle jusqu'à la fin du fichier
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
CREATE TABLE IF NOT EXISTS curseur(id INTEGER PRIMARY KEY CHECK (id = 1), inode INTEGER NOT NULL, octet INTEGER NOT NULL);
"""


log = logging.getLogger("secubox.waf.leurres")


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
        self._prete = False
        self._vue: Optional[dict] = None       # instantané des agrégats, recalculé seulement quand la base change

    # ── base ────────────────────────────────────────────────────────────
    @contextlib.contextmanager
    def _ouvrir(self):
        """Connexion validée puis FERMÉE à la sortie ; schéma et droits posés une fois par processus."""
        c = sqlite3.connect(self.chemin, timeout=10)
        try:
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA foreign_keys = ON")
            if not self._prete or not self.chemin.exists():
                c.executescript(_SCHEMA)
                self._droits()
                self._prete = True
            with c:
                yield c
        finally:
            c.close()

    def _droits(self) -> None:
        """0660 quel que soit l'umask (secubox-waf-ng.service fait `chown -R secubox-waf` sur ce répertoire, même piège
        que ai-ban.jsonl, #3716) et AUCUNE entrée d'ACL nommée : le répertoire donne par défaut la lecture à
        secubox-live (page publique d'état), qui n'a pas à lire 30 jours de mots de passe indexés."""
        try:
            st = os.stat(self.chemin)
            if st.st_uid != os.geteuid():
                return
            with contextlib.suppress(OSError):          # pas d'ACL, ou système de fichiers sans ACL
                os.removexattr(self.chemin, "system.posix_acl_access")
            if os.stat(self.chemin).st_mode & 0o777 != 0o660:
                os.chmod(self.chemin, 0o660)
        except OSError as e:
            log.warning("leurres : droits de la base non posés : %s", e)

    # ── ingestion ───────────────────────────────────────────────────────
    def _avaler(self, c: sqlite3.Connection, chemin: Path, octet: int, maintenant: int) -> tuple:
        """Lit `chemin` depuis `octet` jusqu'à sa fin, par tranches ; rend (visites ajoutées, octet après la dernière
        ligne complète). Une tranche pleine sans fin de ligne est sautée (ligne aberrante), pas attendue pour toujours."""
        n = 0
        try:
            with open(chemin, "rb") as f:
                while True:
                    f.seek(octet)
                    brut = f.read(TRANCHE)
                    fin = brut.rfind(b"\n") + 1
                    if not fin:
                        if len(brut) < TRANCHE:
                            return n, octet                 # ligne partielle : attendue au tour suivant
                        log.warning("leurres : %d octets sans fin de ligne dans %s, sautés", TRANCHE, chemin)
                        fin = len(brut)
                    n += self._inserer(c, brut[:fin].splitlines(), maintenant)
                    octet += fin
        except OSError as e:
            log.warning("leurres : lecture de %s interrompue : %s", chemin, e)
            return n, octet

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
                        n += self._avaler(c, ancien, octet, maintenant)[0]
                    else:
                        log.warning("leurres : ancien journal introuvable après rotation, sa fin n'est pas lue")
                except OSError:
                    log.warning("leurres : ancien journal introuvable après rotation, sa fin n'est pas lue")
                octet = 0
            elif st.st_size < octet:
                octet = 0                      # tronqué sur place
            ajoutees, octet = self._avaler(c, self.journal, octet, maintenant)
            n += ajoutees
            c.execute("INSERT INTO curseur(id, inode, octet) VALUES (1, ?, ?) "
                      "ON CONFLICT(id) DO UPDATE SET inode = excluded.inode, octet = excluded.octet",
                      (st.st_ino, octet))
            return n

    def purger(self, maintenant: int) -> int:
        with self._verrou, self._ouvrir() as c:
            return c.execute("DELETE FROM visites WHERE ts < ?", (maintenant - FENETRE_S,)).rowcount

    # ── lectures ────────────────────────────────────────────────────────
    # Tous les agrégats viennent d'UN instantané, recalculé seulement quand la base a changé (ou d'heure, pour la
    # fenêtre glissante) : une page ouverte, son rafraîchissement et la frappe dans le filtre ne relisent pas 30 jours.
    def _instantane(self, maintenant: int) -> dict:
        depuis = maintenant - FENETRE_S
        with self._verrou, self._ouvrir() as c:
            r = c.execute("SELECT COALESCE(MAX(id), 0) AS m, COUNT(*) AS n FROM visites").fetchone()
            cle = (r["m"], r["n"], maintenant // 3600)
            if self._vue is not None and self._vue["cle"] == cle:
                return self._vue
            visites = c.execute("SELECT id, ip, service, profil, client, ts FROM visites WHERE ts >= ? ORDER BY ts, id",
                                (depuis,)).fetchall()
            essais = c.execute("SELECT v.ip, e.compte, e.mdp FROM essais e JOIN visites v ON v.id = e.visite "
                               "WHERE v.ts >= ? ORDER BY v.ts, v.id, e.rang", (depuis,)).fetchall()
        par_ip: Dict[str, dict] = {}
        par_leurre: Dict[str, int] = {}
        client: Dict[str, dict] = {}
        for v in visites:
            a = par_ip.setdefault(v["ip"], {"ip": v["ip"], "services": set(), "profil": 0, "client": "",
                                             "clients": set(), "visites": 0, "premiere": v["ts"], "derniere": v["ts"],
                                             "essais": {}, "_mdp": {}})
            a["services"].add(v["service"])
            a["profil"] = max(a["profil"], v["profil"])
            a["visites"] += 1
            a["derniere"] = v["ts"]
            par_leurre[v["service"]] = par_leurre.get(v["service"], 0) + 1
            if v["client"]:
                a["client"] = v["client"]
                a["clients"].add(v["client"])
                if v["ip"] != "local":
                    k = client.setdefault(v["client"], {"services": set(), "adresses": set()})
                    k["services"].add(v["service"])
                    k["adresses"].add(v["ip"])
        mdp: Dict[str, dict] = {}
        comptes: Dict[str, dict] = {}
        couples: Dict[tuple, set] = {}
        for e in essais:
            a = par_ip[e["ip"]]
            a["essais"][(e["compte"], e["mdp"])] = None            # dict : ordre d'apparition, sans doublon
            if e["mdp"] and e["compte"]:
                a["_mdp"].setdefault(e["mdp"], set()).add(e["compte"])
            couples.setdefault((e["compte"], e["mdp"]), set()).add(e["ip"])
            m = mdp.setdefault(e["mdp"], {"comptes": set(), "adresses": set(), "essais": 0})
            m["essais"] += 1
            m["adresses"].add(e["ip"])
            if e["compte"]:
                m["comptes"].add(e["compte"])
                k = comptes.setdefault(e["compte"], {"adresses": set(), "essais": 0})
                k["essais"] += 1
                k["adresses"].add(e["ip"])
        attaquants = []
        for a in sorted(par_ip.values(), key=lambda x: -x["derniere"]):
            liste = [{"compte": k[0], "mot_de_passe": k[1]} for k in a["essais"]]
            attaquants.append({
                "ip": a["ip"], "services": sorted(a["services"]), "profil": _NOMS_PROFIL[a["profil"]],
                "client": a["client"], "visites": a["visites"], "premiere": a["premiere"], "derniere": a["derniere"],
                "nb_essais": len(liste), "essais": liste[:5], "rejeu": any(len(x) > 1 for x in a["_mdp"].values()),
                "_foin": "\n".join([a["ip"], *a["clients"], *(k[0] + "\n" + k[1] for k in a["essais"])]).lower()})
        dehors = lambda ips: {i for i in ips if i != "local"}  # noqa: E731
        rejeux = {
            "mot_de_passe_plusieurs_comptes": [
                {"mot_de_passe": k, "comptes": sorted(v["comptes"])[:20], "adresses": len(dehors(v["adresses"]))}
                for k, v in sorted(mdp.items(), key=lambda kv: (-len(kv[1]["comptes"]), kv[0]))
                if k and len(v["comptes"]) > 1 and dehors(v["adresses"])],
            "couple_plusieurs_adresses": [
                {"compte": k[0], "mot_de_passe": k[1], "adresses": sorted(dehors(v))[:200],
                 "blocs": len({_bloc(ip) for ip in dehors(v)})}
                for k, v in sorted(couples.items(), key=lambda kv: (-len(kv[1]), kv[0]))
                if (k[0] or k[1]) and len(dehors(v)) > 1],
            "client_plusieurs_leurres": [
                {"client": k, "services": sorted(v["services"]), "adresses": len(v["adresses"])}
                for k, v in sorted(client.items(), key=lambda kv: (-len(kv[1]["services"]), kv[0]))
                if len(v["services"]) > 1],
        }
        self._vue = {
            "cle": cle, "attaquants": attaquants, "rejeux": rejeux,
            "dictionnaire": {
                "couples": len(couples),
                "mots_de_passe": [{"mot_de_passe": k, "comptes": len(v["comptes"]), "adresses": len(v["adresses"]),
                                   "essais": v["essais"]}
                                  for k, v in sorted(mdp.items(), key=lambda kv: (-kv[1]["essais"], kv[0]))],
                "comptes": [{"compte": k, "adresses": len(v["adresses"]), "essais": v["essais"]}
                            for k, v in sorted(comptes.items(), key=lambda kv: (-kv[1]["essais"], kv[0]))]},
            "resume": {"attaquants": sum(1 for a in attaquants if a["ip"] != "local"), "touches": len(visites),
                       "couples": len(couples), "rejeux": sum(len(v) for v in rejeux.values()),
                       "par_leurre": par_leurre, "premiere": visites[0]["ts"] if visites else None,
                       "fenetre_jours": FENETRE_S // 86400},
        }
        return self._vue

    def attaquants(self, maintenant: int, filtre: str = "", profil: str = "", limite: int = 200) -> List[dict]:
        f = filtre.strip().lower()
        sortie = []
        for a in self._instantane(maintenant)["attaquants"]:
            if (profil and profil != a["profil"]) or (f and f not in a["_foin"]):
                continue
            sortie.append({k: v for k, v in a.items() if k != "_foin"})
            if len(sortie) >= limite:
                break
        return sortie

    def adresses(self, maintenant: int) -> List[str]:
        return [a["ip"] for a in self._instantane(maintenant)["attaquants"]]

    def fiche(self, ip: str, maintenant: int) -> dict:
        with self._verrou, self._ouvrir() as c:
            lignes = c.execute("SELECT * FROM visites WHERE ip = ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT 501",
                               (ip, maintenant - FENETRE_S)).fetchall()
            visites = [dict(id=v["id"], ts=v["ts"], service=v["service"], profil=_NOMS_PROFIL[v["profil"]],
                            client=v["client"], action=v["action"], essais=[]) for v in lignes[:500]]
            par_id = {v["id"]: v for v in visites}
            if par_id:
                for e in c.execute("SELECT visite, compte, mdp FROM essais WHERE visite IN (%s) ORDER BY visite, rang"
                                   % ",".join("?" * len(par_id)), tuple(par_id)):
                    par_id[e["visite"]]["essais"].append({"compte": e["compte"], "mot_de_passe": e["mdp"]})
        for v in visites:
            del v["id"]
        return {"ip": ip, "visites": visites, "tronquee": len(lignes) > 500}

    def dictionnaire(self, maintenant: int, limite: int = 50) -> dict:
        d = self._instantane(maintenant)["dictionnaire"]
        return {"couples": d["couples"], "mots_de_passe": d["mots_de_passe"][:limite], "comptes": d["comptes"][:limite],
                "total_mots_de_passe": len(d["mots_de_passe"])}

    def rejeux(self, maintenant: int, limite: int = 30) -> dict:
        return {k: v[:limite] for k, v in self._instantane(maintenant)["rejeux"].items()}

    def resume(self, maintenant: int) -> dict:
        return dict(self._instantane(maintenant)["resume"])

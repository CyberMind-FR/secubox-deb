# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: POC « DNS AdBlock TV » (#1943).

MESURER ce que le filtrage DNS bloque réellement, pour des appareils choisis (les Freebox TV) — sans toucher aux autres clients ni aux
658 316 domaines du puits DNS de production. On NE supprime PAS de publicité : on mesure la réduction des domaines
publicitaires / de pistage RÉSOLUS par DNS. Aucun MITM, aucun cookie, aucune URL : on ne voit qu'un nom de domaine, un client, une
décision et une heure.

Trois modes par appareil (une « vue » Unbound par appareil, voir `rendre_unbound`) :
  off      l'appareil est RETIRÉ du périmètre du POC : il est traité comme tout le LAN (puits de production) ;
  observe  AUCUN blocage : les requêtes sont journalisées et classées (ce qui AURAIT été bloqué) ;
  block    les domaines des listes du POC répondent NXDOMAIN.

Ce module est une bibliothèque : analyseur du journal d'Unbound, classeur de domaines, état, magasin SQLite, génération de la
configuration Unbound. Il est utilisé par le contrôleur root (`secubox-adguard-tv`), le démon d'alimentation
(`secubox-adguard-dnsfeed`) et l'API (routes `/adblock-tv/*`).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

CATEGORIES = ("advertising", "tracking", "telemetry", "social", "custom")
MODES = ("off", "observe", "block")
DECISIONS = ("ALLOWED", "BLOCKED", "UPSTREAM_ERROR")

ETAT_DEFAUT = {"actif": False, "clients": []}
DOSSIER_ETAT = Path(os.environ.get("SECUBOX_ADGUARD_TV_ETAT", "/var/lib/secubox/ad-guard/dnstv"))
DOSSIER_LISTES = Path(os.environ.get("SECUBOX_ADGUARD_TV_LISTES", "/usr/share/secubox/ad-guard/lists"))
CONF_UNBOUND = Path(os.environ.get("SECUBOX_ADGUARD_TV_UNBOUND", "/etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf"))

# Un nom de domaine, jamais autre chose : ces valeurs finissent dans une configuration Unbound écrite par root.
LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DOMAINE_RE = re.compile(rf"^(?:{LABEL}\.)+[a-z0-9-]{{2,63}}$")
NOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")
ACTIONS_BLOQUANTES = {"always_nxdomain", "always_null", "always_refuse", "refuse", "deny", "inform_deny", "always_transparent_deny"}


class ErreurTV(ValueError):
    """Entrée refusée ; le message est sûr à montrer."""


# ── domaines et listes ───────────────────────────────────────────────────────

def valider_domaine(brut: str) -> Optional[str]:
    """Rend le domaine normalisé (minuscules, sans point final), ou None s'il n'est pas un nom de domaine propre."""
    if not isinstance(brut, str):
        return None
    d = brut.strip().lower().rstrip(".")
    if not d or len(d) > 253 or not DOMAINE_RE.match(d):
        return None
    return d


def lire_liste(chemin: Path) -> Tuple[List[str], List[str], Optional[str]]:
    """(domaines valides, lignes refusées, version annoncée par `# version:`)."""
    bons: List[str] = []
    mauvaises: List[str] = []
    version = None
    for n, ligne in enumerate(chemin.read_text(encoding="utf-8").splitlines(), 1):
        brut = ligne.split("#", 1)[0].strip()
        if ligne.lstrip().startswith("# version:"):
            version = ligne.split(":", 1)[1].strip()
        if not brut:
            continue
        d = valider_domaine(brut)
        (bons if d else mauvaises).append(d or f"{chemin.name}:{n}: {brut[:60]}")
    return bons, mauvaises, version


def sha256_fichier(chemin: Path) -> str:
    return hashlib.sha256(chemin.read_bytes()).hexdigest()


def verifier_manifeste(dossier: Path) -> List[str]:
    """Problèmes de versionnement/validation des listes livrées (vide = tout concorde)."""
    problemes: List[str] = []
    man = dossier / "MANIFEST.json"
    if not man.is_file():
        return ["MANIFEST.json absent"]
    try:
        attendu = json.loads(man.read_text())
    except ValueError:
        return ["MANIFEST.json illisible"]
    for cat in CATEGORIES:
        f = dossier / f"{cat}.txt"
        if cat == "custom":
            continue                                               # la liste perso est celle de l'exploitant, jamais figée
        if not f.is_file():
            problemes.append(f"{cat}.txt absent")
            continue
        if attendu.get(f.name) != sha256_fichier(f):
            problemes.append(f"{f.name}: empreinte différente du manifeste (modifiée sans mise à jour du manifeste)")
        _, mauvaises, _ = lire_liste(f)
        problemes += [f"ligne invalide {m}" for m in mauvaises]
    return problemes


def charger_listes(dossier_livre: Path, perso: Optional[Path] = None) -> Dict[str, str]:
    """domaine -> catégorie. Une liste personnalisée de l'exploitant passe AVANT les listes livrées."""
    out: Dict[str, str] = {}
    for cat in CATEGORIES:
        f = (perso if cat == "custom" and perso else dossier_livre / f"{cat}.txt")
        if f and f.is_file():
            for d in lire_liste(f)[0]:
                out[d] = cat
    return out


class Classifieur:
    """Un nom est classé si lui-même OU l'un de ses domaines parents est dans une liste (a.b.ads.example → ads.example)."""

    def __init__(self, table: Dict[str, str]):
        self.table = table

    def classer(self, qname: str) -> Tuple[Optional[str], Optional[str]]:
        d = valider_domaine(qname)
        if not d:
            return None, None
        etiq = d.split(".")
        for i in range(len(etiq) - 1):
            reste = ".".join(etiq[i:])
            if reste in self.table:
                return self.table[reste], reste
        return None, None


# ── état (périmètre du POC) ──────────────────────────────────────────────────

def _ip(valeur: str) -> str:
    try:
        return str(ipaddress.ip_address(str(valeur).strip()))
    except ValueError:
        raise ErreurTV("adresse IP invalide") from None


def valider_etat(brut) -> dict:
    """État du POC validé en profondeur. Le contrôleur root ne se fie à RIEN d'autre que ce qui passe ici."""
    if not isinstance(brut, dict):
        raise ErreurTV("état illisible")
    clients, vus = [], set()
    if not isinstance(brut.get("clients", []), list):
        raise ErreurTV("la liste d'appareils est invalide")
    for c in brut.get("clients", []):
        if not isinstance(c, dict):
            raise ErreurTV("client invalide")
        ip = _ip(c.get("ip", ""))
        mode = c.get("mode", "observe")
        nom = str(c.get("nom", ip))
        if mode not in MODES:
            raise ErreurTV("mode inconnu (off, observe, block)")
        if not NOM_RE.match(nom):
            raise ErreurTV("nom d'appareil invalide (lettres, chiffres, espace . _ -, 40 caractères au plus)")
        if ip in vus:
            raise ErreurTV("adresse déjà déclarée")
        vus.add(ip)
        clients.append({"ip": ip, "nom": nom, "mode": mode})
    if len(clients) > 32:
        raise ErreurTV("32 appareils au plus")
    return {"actif": bool(brut.get("actif", False)), "clients": clients}


def lire_etat(dossier: Path = None) -> Tuple[dict, Optional[str]]:
    """(état, erreur). Un état absent = POC inactif ; un état CORROMPU = POC inactif ET l'erreur est rendue (jamais d'état deviné)."""
    f = (dossier or DOSSIER_ETAT) / "etat.json"
    if not f.is_file():
        return dict(ETAT_DEFAUT, clients=[]), None
    try:
        return valider_etat(json.loads(f.read_text())), None
    except (ValueError, OSError) as e:
        return dict(ETAT_DEFAUT, clients=[]), f"état invalide, POC laissé inactif ({e})"


def ecrire_etat(etat: dict, dossier: Path = None) -> dict:
    etat = valider_etat(etat)
    d = dossier or DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".etat.")
    with os.fdopen(fd, "w") as h:
        json.dump(etat, h, indent=2)
    os.replace(tmp, d / "etat.json")                              # remplacement atomique : un arrêt brutal ne laisse pas un fichier coupé
    return etat


# ── configuration Unbound ────────────────────────────────────────────────────

def rendre_unbound(etat: dict, table: Dict[str, str]) -> str:
    """Drop-in Unbound du POC. Journalisation par requête + UNE VUE PAR MODE pour les appareils du périmètre.

    Pourquoi des vues et pas des listes globales : (1) les autres clients ne sont pas touchés ; (2) l'appareil en OBSERVE échappe au puits
    de production (sinon on ne verrait jamais « ce qu'il résout sans filtre ») ; (3) retirer le fichier remet tout en l'état.
    Pourquoi `local-zone: "." transparent` dans chaque vue : une vue VIDE n'exempte personne (mesuré avec Unbound 1.22 : le client reste
    bloqué par les zones globales) ; avec une zone transparente qui couvre tout, aucun nom ne retombe sur les zones globales.
    """
    etat = valider_etat(etat)
    L = ["# GÉNÉRÉ par secubox-adguard-tv (secubox-ad-guard) — ne pas éditer (#1943).",
         "# POC « DNS AdBlock TV » : mesure du filtrage DNS. Retirer ce fichier remet tout en l'état.",
         "server:",
         "    log-queries: yes", "    log-replies: yes", "    log-local-actions: yes", "    log-tag-queryreply: yes"]
    suivis = [c for c in etat["clients"] if c["mode"] != "off"]
    if etat["actif"]:
        for c in suivis:
            hote = "/128" if ":" in c["ip"] else "/32"
            L.append(f"    access-control-view: {c['ip']}{hote} sbx-tv-{c['mode']}")
        # NB : les tampons de vue sont déclarés APRÈS « server: ».
        L.append("view:")
        L.append('    name: "sbx-tv-observe"')
        L.append('    local-zone: "." transparent')
        L.append("view:")
        L.append('    name: "sbx-tv-block"')
        for d in sorted(table):
            L.append(f'    local-zone: "{d}." always_nxdomain')
        L.append('    local-zone: "." transparent')
    return "\n".join(L) + "\n"


# ── journal d'Unbound ────────────────────────────────────────────────────────

@dataclass
class Evenement:
    ts: int
    client: str
    qname: str
    qtype: str
    rcode: str
    decision: str


RE_ACTION = re.compile(r"info: (?P<zone>\S+) (?P<action>[a-z_]+) (?P<client>[0-9a-fA-F:.]+)@\d+ (?P<qname>\S+) (?P<qtype>\S+) IN\s*$")
RE_REPLY = re.compile(r"(?:^|\s)reply: (?P<client>[0-9a-fA-F:.]+) (?P<qname>\S+) (?P<qtype>\S+) IN (?P<rcode>[A-Z]+) ")
RE_TS = re.compile(r"^\[(\d+)\]")


class Analyseur:
    """Transforme les lignes du journal d'Unbound en événements. La ligne « action locale » précède la réponse de la même requête ;
    on la retient le temps de lire la réponse (une requête = un événement, avec sa décision)."""

    def __init__(self):
        self._actions: Dict[Tuple[str, str, str], str] = {}

    def ligne(self, ligne: str) -> Optional[Evenement]:
        m = RE_ACTION.search(ligne)
        if m:
            if len(self._actions) > 4096:                          # un client qui boucle ne fait pas grossir la mémoire
                self._actions.clear()
            self._actions[(m["client"], m["qname"].lower().rstrip("."), m["qtype"])] = m["action"]
            return None
        m = RE_REPLY.search(ligne)
        if not m:
            return None
        ts = RE_TS.match(ligne)
        client, qname, qtype, rcode = m["client"], m["qname"].lower().rstrip("."), m["qtype"], m["rcode"]
        action = self._actions.pop((client, qname, qtype), None)
        if action in ACTIONS_BLOQUANTES:
            decision = "BLOCKED"
        elif rcode in ("SERVFAIL", "REFUSED", "FORMERR", "NOTIMP"):
            decision = "UPSTREAM_ERROR"
        else:
            decision = "ALLOWED"
        return Evenement(int(ts.group(1)) if ts else int(time.time()), client, qname, qtype, rcode, decision)


# ── magasin ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS dnstv_counts (
    jour TEXT NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (jour, client, domaine, decision)
);
CREATE TABLE IF NOT EXISTS dnstv_clients (
    client TEXT PRIMARY KEY, premiere_vue INTEGER NOT NULL, derniere_vue INTEGER NOT NULL, total INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS dnstv_counts_jour ON dnstv_counts(jour);
"""


def _jour(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


class Magasin:
    def __init__(self, chemin: Path):
        self.chemin = Path(chemin)
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        with self._cx() as cx:
            cx.executescript(SCHEMA)

    def _cx(self):
        cx = sqlite3.connect(self.chemin, timeout=10)
        cx.execute("PRAGMA journal_mode=WAL")
        return cx

    def ajouter(self, evts: Iterable[Tuple[Evenement, Optional[str]]]) -> int:
        n = 0
        with self._cx() as cx:
            for e, cat in evts:
                cx.execute("INSERT INTO dnstv_counts(jour,client,domaine,categorie,decision,hits) VALUES (?,?,?,?,?,1) "
                           "ON CONFLICT(jour,client,domaine,decision) DO UPDATE SET hits=hits+1, categorie=excluded.categorie",
                           (_jour(e.ts), e.client, e.qname, cat or "", e.decision))
                cx.execute("INSERT INTO dnstv_clients(client,premiere_vue,derniere_vue,total) VALUES (?,?,?,1) "
                           "ON CONFLICT(client) DO UPDATE SET derniere_vue=max(derniere_vue,excluded.derniere_vue), total=total+1",
                           (e.client, e.ts, e.ts))
                n += 1
        return n

    def statistiques(self, client: Optional[str] = None, depuis_jour: Optional[str] = None) -> dict:
        w, a = ["1=1"], []
        if client:
            w.append("client=?")
            a.append(client)
        if depuis_jour:
            w.append("jour>=?")
            a.append(depuis_jour)
        cond = " AND ".join(w)
        with self._cx() as cx:
            total, uniques = cx.execute(f"SELECT COALESCE(SUM(hits),0), COUNT(DISTINCT domaine) FROM dnstv_counts WHERE {cond}", a).fetchone()
            par_cat = dict(cx.execute(f"SELECT categorie, SUM(hits) FROM dnstv_counts WHERE {cond} AND categorie!='' GROUP BY categorie", a).fetchall())
            par_dec = dict(cx.execute(f"SELECT decision, SUM(hits) FROM dnstv_counts WHERE {cond} GROUP BY decision", a).fetchall())
            # « résolus » : domaines classés pub/pistage qui ont reçu une VRAIE réponse ; « bloqués » : ceux refusés par le puits.
            resolus = dict(cx.execute(f"SELECT categorie, SUM(hits) FROM dnstv_counts WHERE {cond} AND categorie!='' AND decision='ALLOWED' GROUP BY categorie", a).fetchall())
            bloques = dict(cx.execute(f"SELECT categorie, SUM(hits) FROM dnstv_counts WHERE {cond} AND decision='BLOCKED' GROUP BY categorie", a).fetchall())
            uniq_cat = dict(cx.execute(f"SELECT categorie, COUNT(DISTINCT domaine) FROM dnstv_counts WHERE {cond} AND categorie!='' GROUP BY categorie", a).fetchall())
        return {"requetes": total, "domaines_uniques": uniques, "par_categorie": par_cat, "par_decision": par_dec,
                "classes_resolus": resolus, "classes_bloques": bloques, "domaines_uniques_par_categorie": uniq_cat}

    def top(self, decision: str = "BLOCKED", limite: int = 20, client: Optional[str] = None) -> List[dict]:
        if decision not in DECISIONS:
            raise ErreurTV("décision inconnue")
        a: list = [decision]
        w = "decision=?"
        if client:
            w += " AND client=?"
            a.append(client)
        with self._cx() as cx:
            return [{"domaine": d, "categorie": c, "hits": h} for d, c, h in cx.execute(
                f"SELECT domaine, categorie, SUM(hits) h FROM dnstv_counts WHERE {w} GROUP BY domaine ORDER BY h DESC LIMIT ?", a + [max(1, min(int(limite), 200))])]

    def lignes(self, client: Optional[str] = None, depuis_jour: Optional[str] = None) -> List[dict]:
        """Tous les compteurs (domaine, catégorie, décision, hits) : sert au calcul AVANT/APRÈS d'une phase de test (différence de deux relevés)."""
        w, a = ["1=1"], []
        if client:
            w.append("client=?")
            a.append(client)
        if depuis_jour:
            w.append("jour>=?")
            a.append(depuis_jour)
        with self._cx() as cx:
            return [{"domaine": d, "categorie": c, "decision": dec, "hits": h} for d, c, dec, h in cx.execute(
                f"SELECT domaine, categorie, decision, SUM(hits) FROM dnstv_counts WHERE {' AND '.join(w)} GROUP BY domaine, categorie, decision", a)]

    def par_client(self) -> List[dict]:
        with self._cx() as cx:
            return [{"client": c, "premiere_vue": p, "derniere_vue": d, "requetes": t}
                    for c, p, d, t in cx.execute("SELECT client, premiere_vue, derniere_vue, total FROM dnstv_clients ORDER BY derniere_vue DESC")]

    def evenements_recents(self, client: str, depuis: int) -> List[dict]:
        """Pour le DNS PATH TEST : ce que cette adresse a demandé depuis `depuis` (ts) — par jour/domaine, jamais de contenu."""
        jour = _jour(depuis)
        with self._cx() as cx:
            return [{"domaine": d, "decision": dec, "categorie": c, "hits": h} for d, dec, c, h in cx.execute(
                "SELECT domaine, decision, categorie, hits FROM dnstv_counts WHERE client=? AND jour>=?", (client, jour))]

    def purger(self, retention_jours: int, maintenant: Optional[int] = None) -> int:
        limite = _jour((maintenant or int(time.time())) - max(1, int(retention_jours)) * 86400)
        with self._cx() as cx:
            return cx.execute("DELETE FROM dnstv_counts WHERE jour<?", (limite,)).rowcount

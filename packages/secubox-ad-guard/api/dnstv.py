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
  block    les domaines des listes du POC répondent NXDOMAIN ;
  auto     vue propre à l'appareil : seules les règles apprises, en essai ou confirmées, répondent NXDOMAIN (#1954).

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
MODES = ("off", "observe", "block", "auto")
DECISIONS = ("ALLOWED", "BLOCKED", "UPSTREAM_ERROR")

ETAT_DEFAUT = {"actif": False, "clients": [], "auto_essai": False, "mode_defaut": "auto", "ajout_auto": False, "ignores": []}
MODES_DEFAUT = ("off", "observe", "auto", "block")
MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
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
    fichiers = [f"{c}.txt" for c in CATEGORIES if c != "custom"] + [k for k in attendu if k not in [f"{c}.txt" for c in CATEGORIES]]
    for nom in fichiers:
        f = dossier / nom
        if not f.is_file():
            problemes.append(f"{nom} absent")
            continue
        if attendu.get(nom) != sha256_fichier(f):
            problemes.append(f"{nom}: empreinte différente du manifeste (modifiée sans mise à jour du manifeste)")
        if nom != "services.txt":                                       # services.txt a trois colonnes ; il a sa propre validation
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

def _slug(nom: str) -> str:
    """Identifiant de vue Unbound d'un appareil : minuscules, tirets ; jamais autre chose que [a-z0-9-]."""
    return re.sub(r"[^a-z0-9]+", "-", str(nom).lower()).strip("-")[:40] or "appareil"


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
            raise ErreurTV("mode inconnu (off, observe, block, auto)")
        if not NOM_RE.match(nom):
            raise ErreurTV("nom d'appareil invalide (lettres, chiffres, espace . _ -, 40 caractères au plus)")
        if ip in vus:
            raise ErreurTV("adresse déjà déclarée")
        vus.add(ip)
        entree = {"ip": ip, "nom": nom, "mode": mode}
        mac = c.get("mac", "")
        if mac and (not isinstance(mac, str) or not MAC_RE.match(mac) or mac == "00:00:00:00:00:00"):
            raise ErreurTV("adresse MAC invalide (minuscules, a:b:c:d:e:f)")
        if mac == "" and "mac" in c and not isinstance(c["mac"], str):
            raise ErreurTV("adresse MAC invalide")
        origine = c.get("origine", "admin")
        if origine not in ("admin", "auto"):
            raise ErreurTV("origine inconnue (admin, auto)")
        ajoute = c.get("ajoute", 0)
        if not isinstance(ajoute, int) or isinstance(ajoute, bool) or ajoute < 0:
            raise ErreurTV("date d'ajout invalide")
        preuve = c.get("preuve", "")
        if not isinstance(preuve, str) or len(preuve) > 120:
            raise ErreurTV("preuve trop longue (120 caractères au plus)")
        puits = c.get("puits", True)
        if not isinstance(puits, bool):
            raise ErreurTV("puits : booléen attendu")
        # Un champ n'est écrit que s'il n'est pas à sa valeur par défaut : les anciens états gardent exactement le même format.
        if mac:
            entree["mac"] = mac
        if origine == "auto":
            entree["origine"] = "auto"
        if ajoute:
            entree["ajoute"] = ajoute
        if preuve:
            entree["preuve"] = preuve
        if not puits:
            entree["puits"] = False
        clients.append(entree)
    if len(clients) > 32:
        raise ErreurTV("32 appareils au plus")
    noms_par_vue: Dict[str, set] = {}
    puits_par_nom: Dict[str, set] = {}
    for c in clients:
        if c["mode"] == "auto":
            noms_par_vue.setdefault(_slug(c["nom"]), set()).add(c["nom"])
            puits_par_nom.setdefault(c["nom"], set()).add(c.get("puits", True))
    if any(len(n) > 1 for n in noms_par_vue.values()):
        raise ErreurTV("deux appareils en mode auto donnent la même vue : leurs noms doivent différer par plus que la casse ou la ponctuation")
    if any(len(p) > 1 for p in puits_par_nom.values()):
        raise ErreurTV("les adresses d'un même appareil doivent avoir le même réglage « puits »")
    auto_essai = brut.get("auto_essai", False)
    if not isinstance(auto_essai, bool):
        raise ErreurTV("auto_essai : booléen attendu")
    ajout_auto = brut.get("ajout_auto", False)
    if not isinstance(ajout_auto, bool):
        raise ErreurTV("ajout_auto : booléen attendu")
    mode_defaut = brut.get("mode_defaut", "auto")
    if mode_defaut not in MODES_DEFAUT:
        raise ErreurTV("mode_defaut inconnu (off, observe, auto, block)")
    ignores_brut = brut.get("ignores", [])
    if not isinstance(ignores_brut, list) or len(ignores_brut) > 64:
        raise ErreurTV("ignores : liste de 64 adresses MAC au plus")
    ignores: List[str] = []
    for m in ignores_brut:
        if not isinstance(m, str) or not MAC_RE.match(m):
            raise ErreurTV("ignores : adresse MAC invalide")
        if m not in ignores:
            ignores.append(m)
    return {"actif": bool(brut.get("actif", False)), "clients": clients, "auto_essai": auto_essai,
            "mode_defaut": mode_defaut, "ajout_auto": ajout_auto, "ignores": ignores}


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

def rendre_unbound(etat: dict, table: Dict[str, str], regles_actives: Optional[Dict[str, List[str]]] = None) -> str:
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
            vue = f"sbx-tv-auto-{_slug(c['nom'])}" if c["mode"] == "auto" else f"sbx-tv-{c['mode']}"
            L.append(f"    access-control-view: {c['ip']}{hote} {vue}")
        # NB : les tampons de vue sont déclarés APRÈS « server: ».
        L.append("view:")
        L.append('    name: "sbx-tv-observe"')
        L.append('    local-zone: "." transparent')
        L.append("view:")
        L.append('    name: "sbx-tv-block"')
        for d in sorted(table):
            L.append(f'    local-zone: "{d}." always_nxdomain')
        L.append('    local-zone: "." transparent')
        # Mode auto : UNE vue par appareil, avec ses seules règles actives (essai ou confirmées).
        for nom in sorted({_slug(c["nom"]) for c in suivis if c["mode"] == "auto"}):
            L.append("view:")
            L.append(f'    name: "sbx-tv-auto-{nom}"')
            puits = all(c.get("puits", True) for c in suivis if c["mode"] == "auto" and _slug(c["nom"]) == nom)
            if puits:
                L.append("    view-first: yes")                  # le puits de production s'applique ET les règles de la vue s'y ajoutent (mesuré, Unbound 1.17.1)
            for d in sorted(set((regles_actives or {}).get(nom, []))):
                if valider_domaine(d) != d:
                    raise ErreurTV("domaine de règle invalide")
                L.append(f'    local-zone: "{d}." always_nxdomain')
            if not puits:
                L.append('    local-zone: "." transparent')           # puits=faux : l'ancien comportement (appareil hors du puits de production)
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
CREATE TABLE IF NOT EXISTS dnstv_recents (
    ts INTEGER NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, qtype TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS dnstv_recents_ts ON dnstv_recents(ts);
CREATE INDEX IF NOT EXISTS dnstv_recents_client ON dnstv_recents(client, ts);
"""
RECENTS_MAX = 20000                      # lignes gardées pour la vue « en direct » et les séries ; au-delà, les plus anciennes partent
RECENTS_HEURES = 48


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

    def ajouter(self, evts: Iterable[Tuple[Evenement, Optional[str]]], exclus: Optional[set] = None) -> int:
        """`exclus` : adresses dont les requêtes ne sont pas journalisées (la box elle-même)."""
        n = 0
        with self._cx() as cx:
            for e, cat in evts:
                if exclus and e.client in exclus:
                    continue
                cx.execute("INSERT INTO dnstv_counts(jour,client,domaine,categorie,decision,hits) VALUES (?,?,?,?,?,1) "
                           "ON CONFLICT(jour,client,domaine,decision) DO UPDATE SET hits=hits+1, categorie=excluded.categorie",
                           (_jour(e.ts), e.client, e.qname, cat or "", e.decision))
                cx.execute("INSERT INTO dnstv_clients(client,premiere_vue,derniere_vue,total) VALUES (?,?,?,1) "
                           "ON CONFLICT(client) DO UPDATE SET derniere_vue=max(derniere_vue,excluded.derniere_vue), total=total+1",
                           (e.client, e.ts, e.ts))
                cx.execute("INSERT INTO dnstv_recents(ts,client,domaine,qtype,decision,categorie) VALUES (?,?,?,?,?,?)",
                           (e.ts, e.client, e.qname, e.qtype, e.decision, cat or ""))
                n += 1
            cx.execute("DELETE FROM dnstv_recents WHERE ts < ? OR rowid <= (SELECT COALESCE(MAX(rowid),0) FROM dnstv_recents) - ?",
                       (int(time.time()) - RECENTS_HEURES * 3600, RECENTS_MAX))
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

    def recents(self, clients: Optional[List[str]] = None, depuis: int = 0, limite: int = 100) -> List[dict]:
        """Les dernières requêtes (la vue « flux en cours »), la plus récente d'abord. `clients` : adresses d'UNE source (IPv4 + IPv6)."""
        w, a = ["ts>=?"], [int(depuis)]
        if clients:
            w.append("client IN (%s)" % ",".join("?" * len(clients)))
            a += list(clients)
        with self._cx() as cx:
            return [{"ts": t, "client": c, "domaine": d, "qtype": q, "decision": dec, "categorie": cat} for t, c, d, q, dec, cat in cx.execute(
                f"SELECT ts, client, domaine, qtype, decision, categorie FROM dnstv_recents WHERE {' AND '.join(w)} ORDER BY ts DESC, rowid DESC LIMIT ?",
                a + [max(1, min(int(limite), 1000))])]

    def serie(self, clients: Optional[List[str]] = None, depuis: int = 0, pas_s: int = 300) -> List[dict]:
        """Requêtes et blocages par tranche de `pas_s` secondes (histogramme)."""
        pas_s = max(10, min(int(pas_s), 86400))
        w, a = ["ts>=?"], [int(depuis)]
        if clients:
            w.append("client IN (%s)" % ",".join("?" * len(clients)))
            a += list(clients)
        with self._cx() as cx:
            return [{"ts": b * pas_s, "requetes": n, "bloquees": bl, "classees": cl} for b, n, bl, cl in cx.execute(
                f"SELECT ts/{pas_s}, COUNT(*), SUM(decision='BLOCKED'), SUM(categorie!='') FROM dnstv_recents WHERE {' AND '.join(w)} GROUP BY ts/{pas_s} ORDER BY 1", a)]

    def flux(self, clients: Optional[List[str]] = None, depuis: int = 0) -> List[dict]:
        """Par nom de domaine : requêtes, décisions, dernière vue (le tableau « équivalent DPI », sans volumes : le DNS n'en a pas)."""
        w, a = ["ts>=?"], [int(depuis)]
        if clients:
            w.append("client IN (%s)" % ",".join("?" * len(clients)))
            a += list(clients)
        with self._cx() as cx:
            return [{"domaine": d, "categorie": c, "requetes": n, "bloquees": b, "derniere": t} for d, c, n, b, t in cx.execute(
                f"SELECT domaine, MAX(categorie), COUNT(*), SUM(decision='BLOCKED'), MAX(ts) FROM dnstv_recents WHERE {' AND '.join(w)} "
                "GROUP BY domaine ORDER BY COUNT(*) DESC LIMIT 500", a)]

    def evenements(self, clients: List[str], depuis: int, limite: int = 20000) -> List[dict]:
        """Événements d'UNE source (toutes ses adresses), du plus ancien au plus récent : sert à la détection des coupures (#1954)."""
        if not clients:
            return []
        with self._cx() as cx:
            lignes = cx.execute(
                "SELECT ts, domaine, decision FROM dnstv_recents WHERE ts>=? AND client IN (%s) ORDER BY ts, rowid LIMIT ?" % ",".join("?" * len(clients)),
                [int(depuis), *clients, max(1, min(int(limite), 50000))]).fetchall()
        return [{"ts": t, "domaine": d, "decision": dec} for t, d, dec in lignes]

    def jours_vus(self, clients: List[str], avant_jour: str, depuis_jour: str = "0000-00-00") -> Dict[str, int]:
        """Domaines réellement servis et nombre de JOURS distincts dans [depuis_jour, avant_jour[ : définit le « contenu habituel » (#1954)."""
        if not clients:
            return {}
        with self._cx() as cx:
            return dict(cx.execute(
                "SELECT domaine, COUNT(DISTINCT jour) FROM dnstv_counts WHERE decision='ALLOWED' AND jour<? AND jour>=? AND client IN (%s) GROUP BY domaine" % ",".join("?" * len(clients)),
                [avant_jour, depuis_jour, *clients]).fetchall())

    def compteurs_clients(self, depuis_jour: str) -> Dict[str, Dict[str, int]]:
        """client -> domaine -> requêtes (toutes décisions) depuis `depuis_jour` : la matière de la détection des TV et streamers (#1959)."""
        out: Dict[str, Dict[str, int]] = {}
        with self._cx() as cx:
            for client, domaine, n in cx.execute("SELECT client, domaine, SUM(hits) FROM dnstv_counts WHERE jour>=? GROUP BY client, domaine", (depuis_jour,)):
                out.setdefault(client, {})[domaine] = int(n)
        return out

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


# ── services : « à qui » et « pour quoi » est un nom (l'équivalent DNS d'une classification DPI) ───────────────────────────
TYPES_SERVICE = ("contenu", "publicite", "mesure_audience", "analytique", "qualite_video", "cdn", "connectivite", "systeme", "inconnu")


def charger_services(chemin: Path) -> List[Tuple[str, str, str]]:
    """Lignes `suffixe  organisation  type` (organisation : libellé court, sans espace superflu ; `_` = espace). Plus long suffixe d'abord."""
    out = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        brut = ligne.split("#", 1)[0].split()
        if len(brut) == 3 and brut[2] in TYPES_SERVICE and valider_domaine(brut[0]):
            out.append((brut[0].lower(), brut[1].replace("_", " "), brut[2]))
    return sorted(out, key=lambda x: -len(x[0]))


class ClasseurServices:
    def __init__(self, regles: List[Tuple[str, str, str]]):
        self.regles = regles

    def classer(self, qname: str) -> Tuple[str, str]:
        d = (qname or "").lower().rstrip(".")
        for suffixe, org, typ in self.regles:
            if d == suffixe or d.endswith("." + suffixe):
                return org, typ
        return "", "inconnu"


def adresses_locales(executer=None) -> set:
    """Toutes les adresses de la box : ses propres requêtes DNS (≈ 11 000 en 20 min) saturaient dnstv_recents (plafond de 20 000 lignes).
    Toujours au moins le bouclage, même si `ip` manque ou échoue."""
    import subprocess
    out = {"127.0.0.1", "::1"}
    try:
        r = (executer or subprocess.run)(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10)
        for itf in json.loads(r.stdout or "[]"):
            for a in itf.get("addr_info", []):
                v = a.get("local")
                if v:
                    out.add(str(ipaddress.ip_address(v)))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return out


def passerelles(executer=None) -> set:
    """Adresses de la passerelle (route par défaut) : jamais détectée ni ajoutée comme appareil (#1959)."""
    import subprocess
    out: set = set()
    try:
        r = (executer or subprocess.run)(["ip", "-j", "route", "show", "default"], capture_output=True, text=True, timeout=10)
        for route in json.loads(r.stdout or "[]"):
            g = route.get("gateway")
            if g:
                out.add(str(ipaddress.ip_address(g)))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return out


def lire_voisins(executer=None) -> Dict[str, str]:
    """adresse IP -> adresse MAC, d'après la table des voisins (IPv4 ET IPv6) : regroupe les adresses d'un même appareil — l'IPv6 « de
    confidentialité » d'une TV change, sa MAC non."""
    import subprocess
    out: Dict[str, str] = {}
    for fam in ("-4", "-6"):
        try:
            r = (executer or subprocess.run)(["ip", "-j", fam, "neigh"], capture_output=True, text=True, timeout=10)
            for n in json.loads(r.stdout or "[]"):
                if n.get("dst") and n.get("lladdr"):
                    out[n["dst"]] = n["lladdr"].lower()
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
    return out


def regrouper_sources(clients: Iterable[str], voisins: Dict[str, str]) -> Dict[str, List[str]]:
    """clé de source (MAC si connue, sinon l'adresse) -> adresses."""
    g: Dict[str, List[str]] = {}
    for c in clients:
        g.setdefault(voisins.get(c, c), []).append(c)
    return g

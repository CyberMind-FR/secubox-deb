# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-meet — activité de la visio (#3182) : réunions, connexions, statistiques.

Deux usages, une seule source :
- `meetctl` (root) l'exécute en script : `collecte` lit sur stdin le journal de LiveKit (`journalctl -o json`, après le
  dernier curseur) et l'écrit dans activite.db ; `comptes` y range les pseudos des comptes de Meet ; `en-direct`, `reunions`
  et `clore` parlent à l'API Twirp de LiveKit avec un jeton signé ici (le secret n'est lu qu'en root, jamais renvoyé).
- l'API (compte secubox) l'importe pour lire activite.db en lecture seule : `historique`, `stats`.

Vie privée : les candidats ICE (adresses IP) ne sont jamais lus ; un participant dont l'identité est le `sub` d'un compte de
Meet apparaît sous son pseudo, tout autre « invité » ; le nom tapé dans Meet et le `turn_password` ne sortent jamais d'ici.
Sessions gardées 30 jours, puis versées dans les totaux par jour et par salle (gardés 12 mois).
Bibliothèque standard seulement.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sqlite3
import statistics
import sys
import time
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Optional

DUREE_SESSIONS_J = 30
DUREE_JOURS_J = 400
SALLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")

MOTIFS = {
    "CLIENT_INITIATED": "a quitté",
    "DUPLICATE_IDENTITY": "rejoint ailleurs",
    "SIGNAL_SOURCE_CLOSE": "connexion perdue",
    "ROOM_DELETED": "réunion close",
    "PARTICIPANT_REMOVED": "retiré",
    "SERVER_SHUTDOWN": "serveur arrêté",
    "JOIN_FAILURE": "échec d'entrée",
    "STATE_MISMATCH": "désynchronisé",
    "MIGRATION": "migration",
}
TRANSPORTS = {"udp": "UDP", "tcp": "TCP", "turn": "Relais"}
# Sorties de psql : `-A -F $'\x1f' -R $'\x1e'`. Un nom de salle est saisi par l'utilisateur : il peut contenir « | » ou un
# retour à la ligne, jamais ces séparateurs ASCII.
CHAMP, ENREG = "\x1f", "\x1e"
SANS_CHEMIN = "aucun chemin média"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY, salle TEXT NOT NULL, identite TEXT NOT NULL, debut INTEGER NOT NULL, actif INTEGER, fin INTEGER,
    transport TEXT, appareil TEXT, pays TEXT, issue TEXT NOT NULL, motif TEXT);
CREATE INDEX IF NOT EXISTS sessions_debut ON sessions(debut);
CREATE TABLE IF NOT EXISTS jours (
    jour TEXT NOT NULL, salle TEXT NOT NULL, abouties INTEGER NOT NULL, echecs INTEGER NOT NULL, secondes INTEGER NOT NULL,
    PRIMARY KEY (jour, salle));
CREATE TABLE IF NOT EXISTS comptes (identite TEXT PRIMARY KEY, pseudo TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL);
"""


# ── Base ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def ouvrir(chemin) -> sqlite3.Connection:
    """Base en écriture (root). Journal en mode DELETE : l'API la lit en lecture seule, sans fichier -shm à créer."""
    cx = sqlite3.connect(str(chemin), timeout=10)
    cx.row_factory = sqlite3.Row
    cx.execute("PRAGMA journal_mode=DELETE")
    cx.executescript(SCHEMA)
    return cx


def ouvrir_lecture(chemin) -> sqlite3.Connection:
    """Base en lecture seule (API). Lève sqlite3.OperationalError si elle n'existe pas encore."""
    cx = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=5)
    cx.row_factory = sqlite3.Row
    return cx


def curseur(cx) -> Optional[str]:
    r = cx.execute("SELECT valeur FROM meta WHERE cle='curseur'").fetchone()
    return r["valeur"] if r else None


# ── Journal de LiveKit → sessions ────────────────────────────────────────────────────────────────────────────────────
def _evenement(ligne: str) -> Optional[Dict[str, Any]]:
    """(type, ts, champs, curseur) d'une entrée `journalctl -o json` de LiveKit ; None pour toute autre ligne."""
    try:
        e = json.loads(ligne)
        msg = e["MESSAGE"]
        ts = int(e["__REALTIME_TIMESTAMP"]) // 1_000_000
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(msg, str):
        return None
    parties = msg.split("\t", 5)
    if len(parties) < 6:
        return None
    try:
        champs = json.loads(parties[5])
    except ValueError:
        return None
    if not isinstance(champs, dict) or not champs.get("participantID") or not champs.get("room"):
        return None
    return {"type": parties[4], "ts": ts, "champs": champs, "curseur": e.get("__CURSOR")}


def _appareil(client) -> Optional[str]:
    if not isinstance(client, dict):
        return None
    morceaux = [str(client.get(k)) for k in ("os", "browser") if client.get(k)]
    return " · ".join(morceaux)[:60] or None


def _motif(raison) -> str:
    r = str(raison or "")
    return MOTIFS.get(r) or r.replace("_", " ").lower()[:40] or "inconnu"


def collecter(cx, lignes: Iterable[str]) -> int:
    """Applique les événements du journal ; rejouer les mêmes lignes ne change rien. Rend le nombre d'événements lus."""
    n, dernier = 0, None
    for ligne in lignes:
        ev = _evenement(ligne)
        if ev is None:
            continue
        n += 1
        dernier = ev["curseur"] or dernier
        c, ts, sid = ev["champs"], ev["ts"], ev["champs"]["participantID"]
        salle, ident = str(c["room"])[:64], str(c.get("participant") or "")[:64]
        cx.execute("INSERT OR IGNORE INTO sessions (sid, salle, identite, debut, issue) VALUES (?, ?, ?, ?, 'en_cours')",
                   (sid, salle, ident, ts))
        if ev["type"] == "participant active":
            cx.execute("UPDATE sessions SET actif=COALESCE(actif, ?), transport=?, appareil=COALESCE(?, appareil), "
                       "issue=CASE WHEN fin IS NULL THEN 'en_cours' ELSE issue END WHERE sid=?",
                       (ts, TRANSPORTS.get(str(c.get("connectionType")), None), _appareil(c.get("clientInfo")), sid))
        elif ev["type"] == "participant closing" and not c.get("isExpectedToResume"):
            pays = str(c.get("country") or "")[:2] or None
            cx.execute("UPDATE sessions SET fin=COALESCE(fin, ?), pays=COALESCE(?, pays), appareil=COALESCE(appareil, ?), "
                       "issue=CASE WHEN issue='echec' THEN issue WHEN actif IS NULL THEN 'abandon' ELSE 'aboutie' END, "
                       "motif=CASE WHEN issue='echec' THEN motif ELSE ? END WHERE sid=?",
                       (ts, pays, _appareil(c.get("clientInfo")), _motif(c.get("reason")), sid))
        elif ev["type"] == "removing participant without connection":
            cx.execute("UPDATE sessions SET fin=COALESCE(fin, ?), issue='echec', motif=? WHERE sid=?", (ts, SANS_CHEMIN, sid))
    if dernier:
        cx.execute("INSERT OR REPLACE INTO meta (cle, valeur) VALUES ('curseur', ?)", (dernier,))
    cx.commit()
    return n


def enregistrements(flux) -> List[str]:
    """Les enregistrements d'une sortie de psql (séparateur \\x1e), sans le saut de ligne final."""
    return [e for e in flux.read().strip("\n").split(ENREG) if e]


def comptes(cx, lignes: Iterable[str]) -> int:
    """`sub` CHAMP `pseudo` (psql sur meet_user) : remplace la table des pseudos."""
    paires = []
    for ligne in lignes:
        morceaux = ligne.strip("\n").split(CHAMP)
        if len(morceaux) == 2 and morceaux[0] and morceaux[1]:
            paires.append((morceaux[0][:64], morceaux[1][:64]))
    cx.execute("DELETE FROM comptes")
    cx.executemany("INSERT OR REPLACE INTO comptes (identite, pseudo) VALUES (?, ?)", paires)
    cx.commit()
    return len(paires)


def _jour(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def _duree(r, maintenant: int) -> int:
    if r["actif"] is None:
        return 0
    return max(0, (r["fin"] if r["fin"] is not None else maintenant) - r["actif"])


def purger(cx, maintenant: Optional[int] = None) -> int:
    """Sessions terminées de plus de 30 jours versées dans `jours`, puis effacées ; `jours` borné à ~13 mois."""
    maintenant = int(maintenant or time.time())
    seuil = maintenant - DUREE_SESSIONS_J * 86400
    vieilles = cx.execute("SELECT * FROM sessions WHERE debut < ? AND fin IS NOT NULL", (seuil,)).fetchall()
    for r in vieilles:
        cx.execute("INSERT INTO jours (jour, salle, abouties, echecs, secondes) VALUES (?, ?, 0, 0, 0) "
                   "ON CONFLICT(jour, salle) DO NOTHING", (_jour(r["debut"]), r["salle"]))
        cx.execute("UPDATE jours SET abouties=abouties+?, echecs=echecs+?, secondes=secondes+? WHERE jour=? AND salle=?",
                   (1 if r["issue"] == "aboutie" else 0, 1 if r["issue"] == "echec" else 0, _duree(r, maintenant),
                    _jour(r["debut"]), r["salle"]))
    cx.execute("DELETE FROM sessions WHERE debut < ? AND fin IS NOT NULL", (seuil,))
    cx.execute("DELETE FROM jours WHERE jour < ?", (_jour(maintenant - DUREE_JOURS_J * 86400),))
    cx.commit()
    return len(vieilles)


# ── Lecture (API) ────────────────────────────────────────────────────────────────────────────────────────────────────
def _pseudos(cx) -> Dict[str, str]:
    return {r["identite"]: r["pseudo"] for r in cx.execute("SELECT identite, pseudo FROM comptes")}


def historique(cx, jours: int = 30, maintenant: Optional[int] = None, salle: Optional[str] = None,
               issue: Optional[str] = None, limite: int = 500) -> List[Dict[str, Any]]:
    """Une ligne par session, la plus récente d'abord. L'identité technique ne sort pas : pseudo ou « invité »."""
    maintenant = int(maintenant or time.time())
    sql, args = "SELECT * FROM sessions WHERE debut >= ?", [maintenant - jours * 86400]
    if salle:
        sql, args = sql + " AND salle = ?", args + [salle]
    if issue:
        sql, args = sql + " AND issue = ?", args + [issue]
    pseudos = _pseudos(cx)
    sortie = []
    for r in cx.execute(sql + " ORDER BY debut DESC LIMIT ?", args + [limite]):
        sortie.append({"sid": r["sid"], "salle": r["salle"], "debut": r["debut"], "fin": r["fin"], "duree": _duree(r, maintenant),
                       "participant": pseudos.get(r["identite"], "invité"), "compte": r["identite"] in pseudos,
                       "appareil": r["appareil"], "transport": r["transport"], "pays": r["pays"], "issue": r["issue"],
                       "motif": r["motif"]})
    return sortie


def _compte(d: Dict[str, int], cle) -> None:
    if cle:
        d[cle] = d.get(cle, 0) + 1


def stats(cx, periode: int = 7, maintenant: Optional[int] = None) -> Dict[str, Any]:
    """Statistiques sur `periode` jours. Le détail (transport, appareils, motifs, pic, médiane) vient des sessions (30 jours
    au plus) ; au-delà, les totaux par jour s'y ajoutent pour les sessions, échecs et secondes."""
    maintenant = int(maintenant or time.time())
    debut = maintenant - periode * 86400
    lignes = cx.execute("SELECT * FROM sessions WHERE debut >= ?", (debut,)).fetchall()
    pseudos = _pseudos(cx)
    abouties = [r for r in lignes if r["issue"] in ("aboutie", "en_cours") and r["actif"] is not None]
    durees = [_duree(r, maintenant) for r in abouties]
    st: Dict[str, Any] = {
        "periode": periode, "sessions": len(lignes), "sessions_abouties": len(abouties),
        "echecs": sum(1 for r in lignes if r["issue"] == "echec"), "secondes": sum(durees),
        "reunions": len({r["salle"] for r in abouties}),
        "participants": {"comptes": len({r["identite"] for r in abouties if r["identite"] in pseudos}),
                         "invites": len({r["identite"] for r in abouties if r["identite"] not in pseudos})},
        "mediane": int(statistics.median(durees)) if durees else None,
        "transport": {}, "motifs": {}, "appareils": {}, "salles": {},
    }
    for r, d in zip(abouties, durees):
        _compte(st["transport"], r["transport"])
        _compte(st["appareils"], r["appareil"])
        st["salles"][r["salle"]] = st["salles"].get(r["salle"], 0) + d
    for r in lignes:
        if r["fin"] is not None:
            _compte(st["motifs"], r["motif"])
    # Pic simultané : balayage des intervalles des sessions abouties.
    bornes = sorted([(r["actif"], 1) for r in abouties] + [((r["fin"] if r["fin"] is not None else maintenant), -1) for r in abouties],
                    key=lambda b: (b[0], b[1]))
    pic, courant, quand = 0, 0, None
    for ts, delta in bornes:
        courant += delta
        if courant > pic:
            pic, quand = courant, ts
    st["pic"] = {"nombre": pic, "quand": quand}
    # Par jour : sessions (récentes) + totaux versés (anciennes).
    par_jour: Dict[str, Dict[str, int]] = {}
    for i in range(periode - 1, -1, -1):
        par_jour[_jour(maintenant - i * 86400)] = {"abouties": 0, "echecs": 0}
    for r in lignes:
        j = par_jour.get(_jour(r["debut"]))
        if j is not None:
            j["abouties"] += 1 if r in abouties else 0
            j["echecs"] += 1 if r["issue"] == "echec" else 0
    for r in cx.execute("SELECT jour, SUM(abouties) a, SUM(echecs) e, SUM(secondes) s FROM jours WHERE jour >= ? GROUP BY jour",
                        (_jour(debut),)):
        st["sessions_abouties"] += r["a"]
        st["echecs"] += r["e"]
        st["secondes"] += r["s"]
        st["sessions"] += r["a"] + r["e"]
        if r["jour"] in par_jour:
            par_jour[r["jour"]]["abouties"] += r["a"]
            par_jour[r["jour"]]["echecs"] += r["e"]
    st["par_jour"] = [{"jour": j, **v} for j, v in par_jour.items()]
    return st


# ── LiveKit (root) ───────────────────────────────────────────────────────────────────────────────────────────────────
def _b64(octets: bytes) -> str:
    return base64.urlsafe_b64encode(octets).rstrip(b"=").decode()


def jeton(cle: str, secret: str, video: Dict[str, Any], maintenant: Optional[int] = None, ttl: int = 60) -> str:
    """Jeton d'API de LiveKit (JWT HS256), valable `ttl` secondes."""
    t = int(maintenant or time.time())
    tete = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    charge = _b64(json.dumps({"iss": cle, "nbf": t - 5, "exp": t + ttl, "video": video}).encode())
    signature = _b64(hmac.new(secret.encode(), f"{tete}.{charge}".encode(), hashlib.sha256).digest())
    return f"{tete}.{charge}.{signature}"


def twirp(url: str, cle: str, secret: str, delai: float = 5.0) -> Callable[[str, Dict, Dict], Dict]:
    """Appelant de l'API RoomService de LiveKit : appel(méthode, corps, droits) -> réponse JSON."""
    def appel(methode: str, corps: Dict, video: Dict) -> Dict:
        req = urllib.request.Request(f"{url.rstrip('/')}/twirp/livekit.RoomService/{methode}", data=json.dumps(corps).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + jeton(cle, secret, video)})
        with urllib.request.urlopen(req, timeout=delai) as r:  # noqa: S310 — URL locale du conteneur, fixée par meetctl
            return json.loads(r.read() or b"{}")
    return appel


def _medias(pistes) -> Dict[str, bool]:
    m = {"son": False, "image": False, "ecran": False}
    for p in pistes or []:
        src, coupe = p.get("source"), bool(p.get("muted"))
        cle = {"MICROPHONE": "son", "CAMERA": "image", "SCREEN_SHARE": "ecran"}.get(src)
        if cle and not coupe:
            m[cle] = True
    return m


def _entier(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def en_direct(appel, cx) -> Dict[str, Any]:
    """Réunions ouvertes et participants, enrichis du transport et de l'appareil relevés dans le journal."""
    pseudos = _pseudos(cx)
    sortie = []
    for salle in appel("ListRooms", {}, {"roomList": True}).get("rooms", []):
        nom = str(salle.get("name") or "")
        if not SALLE_RE.match(nom):
            continue
        ps = []
        for p in appel("ListParticipants", {"room": nom}, {"roomAdmin": True, "room": nom}).get("participants", []):
            ident, sid = str(p.get("identity") or ""), str(p.get("sid") or "")
            vu = cx.execute("SELECT transport, appareil FROM sessions WHERE sid = ?", (sid,)).fetchone()
            ps.append({"sid": sid[:40], "participant": pseudos.get(ident, "invité"), "compte": ident in pseudos,
                       "depuis": _entier(p.get("joined_at")), "medias": _medias(p.get("tracks")),
                       "transport": vu["transport"] if vu else None, "appareil": vu["appareil"] if vu else None})
        sortie.append({"salle": nom, "debut": _entier(salle.get("creation_time")), "participants": ps})
    return {"salles": sortie, "releve": int(time.time())}


def reunions(lignes: Iterable[str], direct: Dict[str, Any], cx) -> List[Dict[str, Any]]:
    """Salles de Meet (id, nom, slug, accès, propriétaire, créée, dernier démarrage ; champs séparés par CHAMP), avec l'état
    en direct et le bilan de la dernière réunion (sessions depuis le dernier démarrage)."""
    ouvertes = {s["salle"]: len(s["participants"]) for s in direct.get("salles", [])}
    sortie = []
    for ligne in lignes:
        m = ligne.strip("\n").split(CHAMP)
        if len(m) != 7 or not SALLE_RE.match(m[0]):
            continue
        rid, nom, slug, acces, proprio, cree, dernier = m
        dernier_ts = _entier(dernier)
        derniere = None
        if dernier_ts is not None:
            r = cx.execute("SELECT COUNT(DISTINCT identite) n, SUM(CASE WHEN actif IS NOT NULL THEN "
                           "COALESCE(fin, CAST(strftime('%s','now') AS INTEGER)) - actif ELSE 0 END) s "
                           "FROM sessions WHERE salle = ? AND debut >= ?", (rid, dernier_ts)).fetchone()
            derniere = {"debut": dernier_ts, "participants": r["n"] or 0, "secondes": max(0, r["s"] or 0)}
        sortie.append({"salle": rid, "nom": nom[:120], "slug": slug[:64], "acces": acces[:20], "proprietaire": proprio[:64] or None,
                       "creee": _entier(cree), "derniere": derniere, "en_cours": rid in ouvertes, "presents": ouvertes.get(rid, 0)})
    sortie.sort(key=lambda x: (x["derniere"] or {}).get("debut") or x["creee"] or 0, reverse=True)
    return sortie


def clore(appel, salle: str) -> Dict[str, Any]:
    """Met fin à une réunion en cours (DeleteRoom) : tous les participants sont déconnectés."""
    if not SALLE_RE.match(salle or ""):
        raise ValueError("nom de salle invalide")
    appel("DeleteRoom", {"room": salle}, {"roomCreate": True})
    return {"success": True, "salle": salle}


# ── Script (meetctl, root) ───────────────────────────────────────────────────────────────────────────────────────────
def _appelant(a) -> Callable:
    with open(a.secret, encoding="utf-8") as f:
        secret = f.read().strip()
    return twirp(a.url, a.cle, secret)


def principal(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="activite", description="Activité de la visio (meetctl).")
    ap.add_argument("commande", choices=["curseur", "collecte", "comptes", "en-direct", "reunions", "clore"])
    ap.add_argument("--db", required=True)
    ap.add_argument("--url", default="http://10.100.0.195:7880")
    ap.add_argument("--cle", default="meet")
    ap.add_argument("--secret", default="/etc/secubox/secrets/meet/livekit-secret")
    ap.add_argument("--salle", default="")
    a = ap.parse_args(argv)
    cx = ouvrir(a.db)
    try:
        if a.commande == "curseur":
            print(curseur(cx) or "")
        elif a.commande == "collecte":
            n = collecter(cx, sys.stdin)
            print(json.dumps({"success": True, "evenements": n, "purgees": purger(cx)}))
        elif a.commande == "comptes":
            print(json.dumps({"success": True, "comptes": comptes(cx, enregistrements(sys.stdin))}))
        elif a.commande == "en-direct":
            print(json.dumps(en_direct(_appelant(a), cx)))
        elif a.commande == "reunions":
            direct = en_direct(_appelant(a), cx)
            print(json.dumps({"reunions": reunions(enregistrements(sys.stdin), direct, cx), "releve": direct["releve"]}))
        else:
            print(json.dumps(clore(_appelant(a), a.salle)))
    except ValueError as e:
        print(json.dumps({"success": False, "error": str(e)}))
        return 1
    except OSError as e:
        print(json.dumps({"success": False, "error": f"LiveKit injoignable : {e}"[:300]}))
        return 1
    finally:
        cx.close()
    return 0


if __name__ == "__main__":
    sys.exit(principal())

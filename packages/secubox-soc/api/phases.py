# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SADE : critères mesurés des phases 3 (Neutralisation locale) et 4 (Apprentissage) (#3839).

Lecture seule de fichiers que gk2 tient déjà, jamais de la base d'un autre module ni de son code (aucun import de
secubox-waf-ng : le lecteur du résumé des indices est recopié ici, avec la même validation). Chaque valeur vaut None
quand sa source manque ou se lit mal : jamais un zéro inventé.

- `ai-ban.jsonl` (journal des gestes du compte ai-ban, `gestes_ia._ecrire_journal`, 0660 groupe secubox-waf dont
  `secubox` est membre) : p3 active = mode `active` ET au moins un `leurre`, ou un `ban` / `ban_bloc` d'office
  (`mode: auto`), daté des dernières 24 h (un ban annulé pour défaut d'audit n'a jamais été posé : écarté) ;
- `waf-threats.log` de sbxwaf (0660, même groupe), puis `waf-threats.log.1` (rotation quotidienne, `delaycompress`)
  quand le fichier courant ne couvre pas 24 h, 16 Mio lus au plus en tout par la fin :
  `rediriges_24h` = SOMME des champs `servies` des lignes `leurre_redirige` (une ligne est bornée par adresse et porte
  le nombre de requêtes servies qu'elle représente ; absent = la ligne seule, 1) ; `tentatives_valides_24h` = lignes
  `action: detect` d'une adresse non locale (détectées puis laissées passer jusqu'au service). Budget épuisé avant
  24 h : `lecture_bornee` vrai, les deux chiffres sont des minimums ;
- `/run/secubox/waf-indices-etat.json` (résumé de secubox-waf-indices, 0644) : `partages`, `revus_chez_pairs`,
  `contenus_chez_pairs` ; cru seulement s'il est un fichier ordinaire à root ou à `secubox`, sans écriture du groupe
  ni des autres, ≤ 64 Kio, daté de moins de 30 min ;
- filtres de l'IA confirmés : gk2 ne connaît pas l'état « confirmé » du relais (gk3) ; il le remplace par « filtre IA
  ACTIF depuis au moins 24 h ». Actifs : cache `/var/lib/secubox/waf/filtres-ia.json` de l'onglet Filtres IA du WAF
  (moins d'une heure) ; date d'application : lignes `leurre_filtres-ia-appliquer` / `-retirer` (résultat `ok`) que
  secubox-cvectl écrit dans `audit.log` (et `.1`), 4 Mio lus au plus par fichier. Un filtre actif jamais vu dans la
  fenêtre lue compte s'il a été posé avant elle (fenêtre ≥ 24 h) ; une ligne d'application tronquée (ids manquants)
  ou une fenêtre trop courte rend la valeur indisponible.

Les mesures sont gardées 60 s (lectures de fichiers bornées, jamais sur chaque appel) ; le mode, lui, est relu en
direct par l'appelant.
"""
import json
import os
import pwd
import re
import stat
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

JOUR_S = 86400
TTL_S = 60.0
BUDGET_MENACES = 16 * 1024 * 1024
BUDGET_JOURNAL_AI = 4 * 1024 * 1024
BUDGET_AUDIT = 4 * 1024 * 1024
TAILLE_RESUME_MAX = 64 * 1024
TAILLE_FILTRES_MAX = 8 * 1024 * 1024
RESUME_PERIME_S = 1800
AVANCE_MAX_S = 60
FILTRES_PERIME_S = 3600
COMPTE_RESUME = "secubox"

DEFAUTS = {
    "SECUBOX_SOC_AI_BAN": "/var/lib/secubox/waf/ai-ban.jsonl",
    "SECUBOX_SOC_WAF_MENACES": "/var/log/secubox/waf/waf-threats.log",
    "SECUBOX_SOC_INDICES": "/run/secubox/waf-indices-etat.json",
    "SECUBOX_SOC_FILTRES_IA": "/var/lib/secubox/waf/filtres-ia.json",
    "SECUBOX_AUDIT_LOG": "/var/log/secubox/audit.log",
}
_RE_ID_FILTRE = re.compile(r"ia-[a-z0-9._-]{1,93}")
_RE_NB_FILTRES = re.compile(r"^\s*(\d{1,4}) filtre")

_verrou = threading.Lock()
_cache: Dict[str, Any] = {}


def _chemin(var: str) -> str:
    return os.environ.get(var) or DEFAUTS[var]


def vider() -> None:
    """Oublie les mesures gardées (tests, et après un geste)."""
    with _verrou:
        _cache.clear()


def _entier(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# ── lecture bornée par la fin ─────────────────────────────────────────────────────────────────────

def _fin(chemin: str, budget: int) -> Optional[Tuple[List[bytes], bool]]:
    """(lignes complètes de la fin, tronqué) ; None si le fichier n'existe pas. Lève OSError s'il est illisible (lien,
    dossier, droits). `tronqué` : le début du fichier n'a pas été lu (la première ligne, coupée, est jetée)."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise OSError("pas un fichier ordinaire")
        taille = os.fstat(f.fileno()).st_size
        debut = max(0, taille - budget)
        f.seek(debut)
        brut = f.read(budget)
    lignes = brut.split(b"\n")
    if debut:
        lignes = lignes[1:]
    if lignes and not brut.endswith(b"\n"):
        lignes = lignes[:-1]  # ligne en cours d'écriture
    return [x for x in lignes if x.strip()], debut > 0


def _json(ligne: bytes) -> Optional[dict]:
    try:
        o = json.loads(ligne)
    except (ValueError, RecursionError):
        return None
    return o if isinstance(o, dict) else None


def _instant(ts: Any) -> Optional[float]:
    """Époque d'un horodatage ISO-8601 AVEC fuseau (sbxwaf : RFC 3339 local ; audit : « …Z ») ; None sinon."""
    if not isinstance(ts, str) or len(ts) > 40:
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.timestamp() if d.tzinfo is not None else None


def _premier_instant(lignes: List[bytes]) -> Optional[float]:
    for x in lignes[:50]:
        o = _json(x)
        t = _instant(o.get("timestamp") or o.get("ts")) if o else None
        if t is not None:
            return t
    return None


def _fenetre(chemin: str, budget: int, depuis: float, filtre: Tuple[bytes, ...]) -> Optional[Tuple[List[dict], bool, Optional[float]]]:
    """Objets des lignes (contenant l'un des `filtre`) du fichier puis, si le fichier courant ne remonte pas jusqu'à
    `depuis`, de sa rotation `.1` — du plus ancien au plus récent. Rend (objets, borné, instant le plus ancien lu) ;
    None si aucun des deux fichiers n'existe. Lève OSError si l'un d'eux est illisible."""
    courant = _fin(chemin, budget)
    if courant is None:
        ancien = _fin(chemin + ".1", budget)
        if ancien is None:
            return None
        morceaux = [ancien]
    else:
        morceaux = [courant]
        t0 = _premier_instant(courant[0])
        if not courant[1] and (t0 is None or t0 > depuis):
            reste = budget - sum(len(x) + 1 for x in courant[0])
            if reste > 0:
                ancien = _fin(chemin + ".1", reste)
                if ancien is not None:
                    morceaux.insert(0, ancien)
    lignes0, tronque0 = morceaux[0]
    plus_ancien = _premier_instant(lignes0)
    borne = tronque0 and (plus_ancien is None or plus_ancien > depuis)
    objets = []
    for lignes, _t in morceaux:
        for x in lignes:
            if any(m in x for m in filtre):
                o = _json(x)
                if o is not None:
                    objets.append(o)
    return objets, borne, plus_ancien


# ── phase 3 ───────────────────────────────────────────────────────────────────────────────────────

def _neutralisation_24h(maintenant: float) -> Optional[bool]:
    """Un leurre, ou un ban / ban_bloc d'office, dans le journal ai-ban sur 24 h ? None si le journal est illisible ;
    False s'il n'existe pas encore (aucun geste n'a jamais été journalisé)."""
    try:
        r = _fin(_chemin("SECUBOX_SOC_AI_BAN"), BUDGET_JOURNAL_AI)
    except OSError:
        return None
    if r is None:
        return False
    entrees = [o for o in (_json(x) for x in r[0]) if o is not None]
    jamais_poses = {e.get("id") for e in entrees if e.get("type") == "annule" and e.get("cause") == "audit"}
    for e in entrees:
        at = e.get("at")
        if not _entier(at) or not maintenant - JOUR_S < at <= maintenant + AVANCE_MAX_S:
            continue
        if not isinstance(e.get("id"), str) or e["id"] in jamais_poses:
            continue
        if e.get("type") == "leurre" or (e.get("type") == "ban" and e.get("mode") == "auto"):
            return True
    return False


def _menaces_24h(maintenant: float) -> Tuple[Optional[int], Optional[int], bool]:
    """(requêtes servies par le leurre, tentatives laissées passer, lecture bornée) sur 24 h."""
    depuis = maintenant - JOUR_S
    try:
        r = _fenetre(_chemin("SECUBOX_SOC_WAF_MENACES"), BUDGET_MENACES, depuis, (b"leurre_redirige", b'"detect"'))
    except OSError:
        return None, None, False
    if r is None:
        return None, None, False
    objets, borne, _ancien = r
    servies = tentatives = 0
    for o in objets:
        t = _instant(o.get("timestamp"))
        if t is None or not depuis < t <= maintenant + AVANCE_MAX_S:
            continue
        if o.get("category") == "leurre_redirige":
            n = o.get("servies", 1)
            if _entier(n) and n >= 0:
                servies += n
        elif o.get("action") == "detect" and o.get("client_ip") not in (None, "", "local") \
                and o.get("severity") != "audit":
            tentatives += 1
    return servies, tentatives, borne


# ── phase 4 ───────────────────────────────────────────────────────────────────────────────────────

def _uids_resume() -> Set[int]:
    try:
        return {0, pwd.getpwnam(COMPTE_RESUME).pw_uid}
    except KeyError:
        return {0}


def indices_etat(maintenant: float) -> Optional[Dict[str, Optional[int]]]:
    """Recopie de `secubox-waf-ng` `indices_ip.indices_etat()` (même validation) : `{"partages", "revus_chez_pairs",
    "contenus_chez_pairs"}` ou None (absent, illisible, d'un autre compte, modifiable par le groupe ou les autres,
    périmé, daté du futur, ou de forme inattendue). Livraisons inconnues : les deux comptes des pairs valent None."""
    fd = -1
    try:
        fd = os.open(_chemin("SECUBOX_SOC_INDICES"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        # root ou `secubox` (le compte même de cette API, d'où geteuid : identique en production)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (_uids_resume() | {os.geteuid()})
                or st.st_mode & 0o022 or st.st_size > TAILLE_RESUME_MAX):
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            d = json.loads(f.read(TAILLE_RESUME_MAX))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    cles = ("partages", "revus_chez_pairs", "contenus_chez_pairs")
    if not isinstance(d, dict) or not _entier(d.get("maj")) or not _entier(d.get("partages")):
        return None
    if not all(d.get(k) is None or _entier(d.get(k)) for k in cles[1:]):
        return None
    if (d.get("revus_chez_pairs") is None) != (d.get("contenus_chez_pairs") is None):
        return None
    age = maintenant - d["maj"]
    if age > RESUME_PERIME_S or age < -AVANCE_MAX_S:
        return None
    return {k: d[k] for k in cles}


def _filtres_actifs(maintenant: float) -> Optional[Set[str]]:
    # fichier JSON entier (écrit sans fin de ligne par remplacement atomique) ; absent ou trop gros : on ne sait pas
    try:
        fd = os.open(_chemin("SECUBOX_SOC_FILTRES_IA"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            brut = f.read(TAILLE_FILTRES_MAX + 1)
        if len(brut) > TAILLE_FILTRES_MAX:
            return None
        d = json.loads(brut)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(d, dict) or not isinstance(d.get("filtres"), list):
        return None
    gen = _instant(d.get("genere_le"))
    if gen is None or not -AVANCE_MAX_S <= maintenant - gen <= FILTRES_PERIME_S:
        return None
    ids = set()
    for f in d["filtres"]:
        fid = f.get("id") if isinstance(f, dict) else None
        if not isinstance(fid, str) or not _RE_ID_FILTRE.fullmatch(fid):
            return None
        ids.add(fid)
    return ids


def filtres_confirmes(maintenant: float) -> Optional[int]:
    """Filtres de l'IA actifs depuis au moins 24 h (substitut gk2 de l'état « confirmé » de gk3), ou None."""
    actifs = _filtres_actifs(maintenant)
    if actifs is None:
        return None
    if not actifs:
        return 0
    depuis = maintenant - JOUR_S
    try:
        r = _fenetre(_chemin("SECUBOX_AUDIT_LOG"), BUDGET_AUDIT, depuis, (b"filtres-ia-",))
    except OSError:
        return None
    if r is None:
        return None
    objets, _borne, plus_ancien = r
    pose: Dict[str, Optional[float]] = {}     # id → instant de la 1re application depuis son dernier retrait
    complet = True
    for o in objets:
        if o.get("module") != "cve-triage" or o.get("result") != "ok":
            continue
        t = _instant(o.get("ts"))
        detail = o.get("detail") if isinstance(o.get("detail"), str) else ""
        if t is None:
            continue
        if o.get("action") == "leurre_filtres-ia-appliquer":
            ids = _RE_ID_FILTRE.findall(detail)
            m = _RE_NB_FILTRES.match(detail)
            if m is None or int(m.group(1)) != len(ids):
                complet = False  # ligne tronquée (audit borné à 500 caractères) : des ids manquent
            for fid in ids:
                if pose.get(fid) is None:
                    pose[fid] = t
        elif o.get("action") == "leurre_filtres-ia-retirer":
            for fid in _RE_ID_FILTRE.findall(detail)[:1]:
                pose[fid] = None
    n = 0
    for fid in actifs:
        if fid in pose:
            t = pose[fid]
            if t is None:
                return None  # retiré sans application relevée depuis, mais actif : incohérent
            n += t <= depuis
        elif complet and plus_ancien is not None and plus_ancien <= depuis:
            n += 1  # posé avant la fenêtre lue, qui couvre déjà 24 h
        else:
            return None
    return n


# ── assemblage ────────────────────────────────────────────────────────────────────────────────────

def _mesures() -> Dict[str, Any]:
    maintenant = time.time()
    with _verrou:
        if _cache.get("expire", 0) > maintenant:
            return _cache["mesures"]
    rediriges, tentatives, borne = _menaces_24h(maintenant)
    ind = indices_etat(maintenant) or {}
    m = {"neutralisation_24h": _neutralisation_24h(maintenant), "rediriges_24h": rediriges,
         "tentatives_valides_24h": tentatives, "lecture_bornee": borne,
         "partages": ind.get("partages"), "revus_chez_pairs": ind.get("revus_chez_pairs"),
         "contenus_chez_pairs": ind.get("contenus_chez_pairs"), "filtres_confirmes": filtres_confirmes(maintenant)}
    with _verrou:
        _cache.update(expire=maintenant + TTL_S, mesures=m)
    return m


def phases(mode: Optional[str]) -> Dict[str, Any]:
    """Bloc `phases` de /defense/status. `active` : True, False, ou None quand la source ne se lit pas."""
    m = _mesures()
    p3 = False if mode != "active" else m["neutralisation_24h"]
    part, filt = m["partages"], m["filtres_confirmes"]
    if (part or 0) > 0 or (filt or 0) > 0:
        p4: Optional[bool] = True
    elif part is not None and filt is not None:
        p4 = False
    else:
        p4 = None
    return {
        "p3": {"livree": True, "active": p3, "lecture_bornee": m["lecture_bornee"],
               "critere": {"rediriges_24h": m["rediriges_24h"], "tentatives_valides_24h": m["tentatives_valides_24h"]}},
        "p4": {"livree": True, "active": p4,
               "critere": {"partages": part, "revus_chez_pairs": m["revus_chez_pairs"],
                           "contenus_chez_pairs": m["contenus_chez_pairs"], "filtres_confirmes": filt}},
    }

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Bannir un acteur depuis sa fiche (#3960) : aperçu obligatoire, geste de l'administrateur, levée en un geste.

sbx-actord reste en lecture seule : il fournit la chronologie (adresse, date) ; le WAF décide et applique.

- `GET /acteurs/{id}/etat` : adresses vues depuis moins de 48 h, combien sont bannies maintenant, gestes actifs ;
- `GET /acteurs/{id}/apercu` : les mêmes adresses en trois groupes, « à bannir » (200 au plus, les plus récentes),
  « déjà bannies », « épargnées » avec leur motif. Rien n'est appliqué ;
- `POST /acteurs/{id}/bannir` `{apercu}` : applique la liste montrée, jamais une adresse de plus. Aperçu de moins de
  5 minutes, du même administrateur, à usage unique ; les protections sont recontrôlées, puis de nouveau en root par
  `wafctl ban-lot` (plages protégées exigées). 24 h, jamais un bloc ;
- `POST /acteurs/gestes/{id}/lever` : retire les seules adresses posées par ce geste. Reste bannie celle dont la fin
  n'est plus celle du geste, ou que sbxwaf tient pour bannie (`bans.jsonl`). Limite connue : une adresse que quelqu'un
  d'autre bannit pour 24 h dans les 20 s qui suivent le geste (75 s si la pose a été interrompue) ne s'en distingue pas ; un ban plus court posé après lui
  est déjà sans effet (elle est bannie) et ne revient pas à la levée, sauf ceux de sbxwaf.

Épargnées : forme ou plage non publique, liste blanche, liste blanche SADE, pair du maillage, adresse d'une session
ouverte ou du demandeur, robot vérifié, robot non vérifiable (DNS en doute) ; les robots ne sont vérifiés qu'à l'aperçu
(5 minutes au plus). Une source de protection illisible refuse le geste (503). Une ligne `demande` (adresses, fin prévue)
est écrite AVANT la pose : un geste interrompu reste visible et levable. Audit avant et après ; sans journal ou audit, le
lot posé est retiré. `partiel` : la chronologie d'actord est bornée (mille événements, parmi ceux qu'il relit).
"""
from __future__ import annotations

import concurrent.futures
import http.client
import json
import logging
import os
import re
import secrets
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core.auth import adresse_client, require_jwt

try:
    from api import garde_ban as _gb
    from api import gestes_ia as _g
except ImportError:  # pragma: no cover — import hors paquet
    import garde_ban as _gb
    import gestes_ia as _g

log = logging.getLogger("secubox.waf.acteurs")

router = APIRouter(prefix="/acteurs", dependencies=[Depends(_g.processus_designe)])

SOCKET_ACTORD = "/run/secubox/actor.sock"
SESSIONS = Path("/var/lib/secubox/auth/sessions.json")
JOURNAL = Path("/var/lib/secubox/waf/acteur-ban.jsonl")
FENETRE_S = 48 * 3600
MAX_ADRESSES = 200
DUREE_S = 86_400
APERCU_S = 300
PLAFOND_HEURE = 10
_LIMITE_EVENEMENTS = 1000          # plafond d'actord : au-delà, seuls les plus récents sont rendus
_TAILLE_MAX = 4 * 1024 * 1024
_DELAI_DNS_LOT_S = 12.0
_RE_ACTEUR = re.compile(r"ACT-[0-9A-Z]{1,12}")
_RE_ID = re.compile(r"[0-9a-f]{32}")

_config: Dict[str, Callable[..., Any]] = {}
_verrou = threading.Lock()
_apercus: Dict[str, dict] = {}
_dns = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="acteur-dns")


def configurer(audit: Callable[[str, str, dict], None], liste_blanche: Callable[[], List[str]],
               apres: Callable[[], None] = lambda: None) -> None:
    """`audit` lève si la ligne n'a pas pu être écrite ; `apres` : vider les caches de bans."""
    _config.update(audit=audit, liste_blanche=liste_blanche, apres=apres)


class DemandeBan(BaseModel):
    model_config = {"extra": "forbid"}

    apercu: str = Field(pattern=r"^[0-9a-f]{32}$")


def _lire_chronologie(acteur: str) -> dict:
    conn = _g._ConnexionUnix(SOCKET_ACTORD, 8.0)
    try:
        conn.request("GET", f"/actors/{acteur}/timeline?limit={_LIMITE_EVENEMENTS}", headers={"X-Sbx-Vue": "complete"})
        rep = conn.getresponse()
        corps = rep.read(_TAILLE_MAX + 1)
    except (OSError, http.client.HTTPException) as e:
        raise HTTPException(503, detail={"motif": "actord"}) from e
    finally:
        conn.close()
    if rep.status == 404:
        raise HTTPException(404, detail={"motif": "inconnu"})
    try:
        doc = json.loads(corps) if rep.status == 200 and len(corps) <= _TAILLE_MAX else None
    except ValueError:
        doc = None
    if not isinstance(doc, dict) or not isinstance(doc.get("events"), list):
        raise HTTPException(503, detail={"motif": "actord"})
    return doc


def _adresses(acteur: str, maintenant: int) -> Tuple[List[Tuple[str, int]], bool]:
    """([(adresse, dernière vue)], lecture partielle), les plus récentes d'abord, fenêtre de 48 h."""
    if not _RE_ACTEUR.fullmatch(acteur):
        raise HTTPException(404, detail={"motif": "inconnu"})
    doc = _lire_chronologie(acteur)
    vues: Dict[str, int] = {}
    for e in doc["events"]:
        if not isinstance(e, dict) or not isinstance(e.get("src_ip"), str) or not _g._entier(e.get("ts")):
            continue
        if maintenant - FENETRE_S <= e["ts"] <= maintenant + 60:
            vues[e["src_ip"]] = max(vues.get(e["src_ip"], 0), e["ts"])
    total = doc.get("total")
    partiel = not _g._entier(total) or total > len(doc["events"])
    return sorted(vues.items(), key=lambda x: (-x[1], x[0])), partiel


def _bannies() -> set:
    try:
        return _g.lire_waf_ban("waf_ban") | _g.lire_waf_ban("waf_ban6")
    except Exception as e:  # noqa: BLE001 — ensemble illisible : jamais « libre » par défaut
        log.warning("acteurs : ensemble illisible : %s", e)
        raise HTTPException(503, detail={"motif": "etat"}) from None


def _reseaux_sessions() -> List[Any]:
    """Adresses des sessions ouvertes. Absent (l'administrateur en a pourtant une) ou illisible : ProtectionInconnue."""
    try:
        doc = json.loads(SESSIONS.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise _g.ProtectionInconnue(f"sessions : {type(e).__name__}") from None
    if isinstance(doc, dict):
        doc = list(doc.values())
    if not isinstance(doc, list):
        raise _g.ProtectionInconnue("sessions : forme inattendue")
    return [n for s in doc if isinstance(s, dict) for n in [_g._reseau_pair(s.get("ip"))] if n is not None]


def _reseau_sur(texte: str) -> Any:
    n = _g._reseau_pair(texte)
    if n is None:
        raise _g.ProtectionInconnue(f"entrée illisible : {texte[:45]!r}")
    return n


def _local(demandeur: str) -> bool:
    """Kiosque ou console de la box : toute la chaîne est locale, aucune adresse publique à protéger."""
    return demandeur in ("", "::1", "localhost") or demandeur.startswith("127.")


def _sade_publiee() -> bool:
    """Le fichier publié par le SOC existe, régulier, à root ou à son compte, fermé en écriture aux autres."""
    try:
        st = os.lstat(_g.FICHIER_SADE)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid in _g._uids_sade() and not st.st_mode & 0o022


def _protections(demandeur: str) -> List[Tuple[str, List[Any]]]:
    """[(motif, réseaux)] ; toute source illisible refuse le geste."""
    publiee = _sade_publiee()          # avant la lecture : un fichier paru entre les deux ne vaut pas une liste vide
    try:
        sade = _g.lire_sade()
        # fichier absent (SOC installé) ou non fiable : lire_sade rend « observe » et une liste vide, que rien ne garantit
        if sade is not None and (sade["liste"] is None or sade["mode"] == "observe" and not sade["liste"]
                                 and not publiee):
            raise _g.Illisible("liste blanche SADE")
        blanche = [x.strip() for x in _config["liste_blanche"]() if x.strip()]
        return [("liste_blanche", [_reseau_sur(x) for x in blanche]),
                ("sade", sade["liste"] if sade else []),
                ("pair", _g.pairs_wg_mesh() + _g.pairs_threatmesh()),
                ("session", _reseaux_sessions() + ([] if _local(demandeur) else [_reseau_sur(demandeur)]))]
    except (_g.ProtectionInconnue, _g.Illisible, OSError, KeyError, TypeError, AttributeError) as e:
        log.warning("acteurs : protection illisible : %s", e)
        raise HTTPException(503, detail={"motif": "protegee_inconnue"}) from None


def _motif_epargne(ip: str, protections: List[Tuple[str, List[Any]]]) -> Optional[str]:
    try:
        a = _gb.adresse_publique(ip)
    except ValueError as e:
        return str(e)
    return next((motif for motif, reseaux in protections if any(_g._touche(a, n) for n in reseaux)), None)


def _robots(ips: List[str], limite: float) -> Dict[str, str]:
    """{adresse: motif} des robots vérifiés et des adresses dont le DNS n'a pas répondu à temps (le doute épargne)."""
    taches = {_dns.submit(_g._fcrdns, ip): ip for ip in ips}
    finies, _ = concurrent.futures.wait(taches, timeout=max(0.0, limite - time.monotonic()))
    out: Dict[str, str] = {}
    for t, ip in taches.items():
        if t not in finies:
            t.cancel()
            out[ip] = "robot_inconnu"
        elif t.exception() is not None:
            out[ip] = "robot_inconnu"
        elif t.result():
            out[ip] = "robot"
    return out


def _qui(user: Any) -> str:
    return str((user or {}).get("sub") or "")


def _lire_journal() -> List[dict]:
    try:
        lignes = _g._lire_fin_jsonl(JOURNAL, _g._TAILLE_LECTURE) or []
    except OSError:
        raise HTTPException(503, detail={"motif": "journal"}) from None
    return [e for e in lignes if isinstance(e, dict) and isinstance(e.get("id"), str) and _RE_ID.fullmatch(e["id"])
            and _g._entier(e.get("at"))
            and (e.get("type") == "leve" or e.get("type") in ("demande", "ban") and isinstance(e.get("cibles"), list)
                 and _g._entier(e.get("fin")) and isinstance(e.get("acteur"), str))]


def _gestes_actifs(entrees: List[dict], maintenant: int) -> List[dict]:
    """Gestes non échus et non levés, `cibles` réduites à ce qui reste. `demande` sans suite : pose interrompue
    (`incertain`). Une ligne `leve` sans `cibles` clôt le geste."""
    gestes: Dict[str, dict] = {}
    for e in entrees:
        if e["type"] != "leve":
            gestes[e["id"]] = {**e, "incertain": e["type"] == "demande"}
        elif e["id"] in gestes:
            g, levees = gestes[e["id"]], e.get("cibles")
            g["cibles"] = [ip for ip in g["cibles"] if ip not in levees] if isinstance(levees, list) else []
    return [g for g in gestes.values() if g["cibles"] and g["fin"] > maintenant]


class Incertain(Exception):
    """wafctl n'a pas répondu clairement : des adresses sont peut-être posées."""


_RE_REFUS = re.compile(r"refus:([a-z_]{1,32})")


def _executer(verbe: str, arguments: List[str], ips: List[str]) -> dict:
    """`sudo wafctl <verbe> <arguments>`, adresses sur l'entrée standard : le document JSON rendu. Refus net (wafctl dit
    pourquoi, rien n'est posé) : HTTPException 503. Sinon `Incertain`."""
    try:
        r = subprocess.run(["sudo", "-n", _g.WAFCTL, verbe, *arguments], input="\n".join(ips) + "\n", check=False,
                           timeout=60, capture_output=True, text=True)
        doc = json.loads(r.stdout) if r.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        raise Incertain(type(e).__name__) from None
    if isinstance(doc, dict):
        return doc
    motif = _RE_REFUS.search(r.stderr or "")
    if r.returncode == 0 or motif is None or motif[1] == "incertain":
        raise Incertain(f"code {r.returncode}")
    log.error("acteurs : wafctl %s : refus %s", verbe, motif[1])
    raise HTTPException(503, detail={"motif": "etat" if motif[1] == "etat" else
                                     "protegee_inconnue" if motif[1] == "garde_illisible" else "wafctl"})


def _liste(doc: dict, cle: str, permises: List[str]) -> List[str]:
    v = doc.get(cle)
    return [ip for ip in permises if isinstance(v, list) and ip in v]


def _retirer(ips: List[str], fin: int, incertain: bool = False) -> bool:
    """Retour arrière d'une pose. True seulement si aucune des adresses ne reste bannie par ce geste."""
    try:
        doc = _executer("unban-lot", [str(fin)] + (["incertain"] if incertain else []), ips)
    except (HTTPException, Incertain):
        doc = {"couverts": ips}
    if doc.get("couverts"):
        log.error("acteurs : retour arrière incomplet (%d adresses)", len(doc["couverts"]))
    return doc.get("couverts") == []


def _clore(ident: str, cause: str, maintenant: int, **champs: Any) -> None:
    """Ligne `leve`. Lève OSError."""
    _gb._ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "leve", "id": ident, "cause": cause, **champs}, JOURNAL)


def _couvertes_par_le_waf(ips: List[str], maintenant: int) -> set:
    """Celles dont le dernier enregistrement de sbxwaf est un ban non échu (une seule lecture de bans.jsonl)."""
    voulues, dernier = set(ips), {}
    try:
        for r in _g._lire_fin_jsonl(_g.BANS_WAF, _g._TAILLE_LECTURE_BANS_WAF) or []:
            if isinstance(r, dict) and r.get("ip") in voulues:
                dernier[r["ip"]] = r
    except OSError:
        raise HTTPException(503, detail={"motif": "etat"}) from None
    return {ip for ip, r in dernier.items() if r.get("action") == "ban"
            and (not _g._entier(r.get("exp")) or r["exp"] == 0 or r["exp"] > maintenant)}


@router.get("/{acteur}/etat")
def etat(acteur: str, _user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    maintenant = int(time.time())
    vues, partiel = _adresses(acteur, maintenant)
    bannies = _bannies()
    # actord renumérote ses acteurs à chaque relance : le numéro noté dans un geste ne désigne plus le même profil. Un
    # geste appartient à la fiche dont il a banni des adresses ; les autres restent levables, à part.
    ips = {ip for ip, _ in vues}
    gestes = _gestes_actifs(_lire_journal(), maintenant)
    return {"acteur": acteur, "vues_48h": len(vues), "bannies": sum(ip in bannies for ip, _ in vues), "partiel": partiel,
            "gestes": [{"id": g["id"], "at": g["at"], "fin": g["fin"], "nombre": len(g["cibles"]),
                        "par": str(g.get("par") or ""), "incertain": g["incertain"],
                        "ici": not ips.isdisjoint(ip for ip in g["cibles"] if isinstance(ip, str))} for g in gestes]}


@router.get("/{acteur}/apercu")
def apercu(acteur: str, request: Request, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    maintenant = int(time.time())
    vues, partiel = _adresses(acteur, maintenant)
    bannies, protections = _bannies(), _protections(adresse_client(request))
    deja, epargnees, candidates = [], [], []
    for ip, vu in vues:
        motif = _motif_epargne(ip, protections)
        if motif:
            epargnees.append({"ip": ip, "motif": motif})
        elif ip in bannies:
            deja.append(ip)
        else:
            candidates.append((ip, vu))
    # les adresses épargnées après coup (robots, DNS muet) sont remplacées par les suivantes, dans un délai unique
    limite, a_bannir = time.monotonic() + _DELAI_DNS_LOT_S, []
    while candidates and len(a_bannir) < MAX_ADRESSES and time.monotonic() < limite:
        n = MAX_ADRESSES - len(a_bannir)
        lot, candidates = candidates[:n], candidates[n:]
        robots = _robots([ip for ip, _ in lot], limite)
        epargnees += [{"ip": ip, "motif": m} for ip, m in robots.items()]
        a_bannir += [{"ip": ip, "vu": vu} for ip, vu in lot if ip not in robots]
    reste = len(candidates)
    ident = secrets.token_hex(16)
    with _verrou:
        for k in [k for k, v in _apercus.items() if maintenant - v["at"] > APERCU_S]:
            del _apercus[k]
        while len(_apercus) >= 50:
            del _apercus[next(iter(_apercus))]
        _apercus[ident] = {"at": maintenant, "acteur": acteur, "par": _qui(user), "ips": [x["ip"] for x in a_bannir]}
    return {"apercu": ident, "expire": maintenant + APERCU_S, "acteur": acteur, "duree_s": DUREE_S, "a_bannir": a_bannir,
            "deja_bannies": len(deja), "epargnees": epargnees, "reste": reste, "partiel": partiel}


@router.post("/{acteur}/bannir")
def bannir(acteur: str, demande: DemandeBan, request: Request, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    with _verrou:
        maintenant = int(time.time())
        ap = _apercus.get(demande.apercu)
        if ap is None or maintenant - ap["at"] > APERCU_S or ap["acteur"] != acteur or ap["par"] != _qui(user):
            raise HTTPException(409, detail={"motif": "apercu_perime"})
        if sum(e["type"] == "demande" and maintenant - e["at"] < 3600 for e in _lire_journal()) >= PLAFOND_HEURE:
            raise HTTPException(409, detail={"motif": "plafond"})
        protections = _protections(adresse_client(request))
        cibles = [ip for ip in ap["ips"] if _motif_epargne(ip, protections) is None]
        if not cibles:
            raise HTTPException(409, detail={"motif": "vide"})
        del _apercus[demande.apercu]                       # usage unique, quel que soit le résultat
        ident = secrets.token_hex(16)
        ligne = {"ts": _g._horodatage(), "at": maintenant, "id": ident, "acteur": acteur, "par": _qui(user)}
        prevue = maintenant + DUREE_S
        try:
            _gb._ecrire_journal({**ligne, "type": "demande", "cibles": cibles, "fin": prevue}, JOURNAL)
        except OSError:
            raise HTTPException(503, detail={"motif": "audit"}) from None
        try:
            _config["audit"]("acteur-ban-demande", f"id {ident} acteur {acteur} {len(cibles)} adresses {DUREE_S}s", user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            _abandonner(ident, "audit", maintenant)
            raise HTTPException(503, detail={"motif": "audit"}) from None
        try:
            doc = _executer("ban-lot", [f"{DUREE_S}s"], cibles)
        except HTTPException:                              # refus net : rien n'est posé, rien n'est à défaire
            _abandonner(ident, "refus", maintenant)
            raise
        except Incertain as e:
            log.error("acteurs : ban-lot incertain : %s", e)
            if _retirer(cibles, prevue, incertain=True):
                _abandonner(ident, "incertain", maintenant)
                raise HTTPException(503, detail={"motif": "wafctl"}) from None
            raise HTTPException(500, detail={"motif": "incoherent"}) from None
        poses = _liste(doc, "poses", cibles)
        refuses = doc["refuses"] if isinstance(doc.get("refuses"), dict) else {}
        fin = doc["fin"] if _g._entier(doc.get("fin")) else prevue
        try:
            _gb._ecrire_journal({**ligne, "type": "ban", "cibles": poses, "fin": fin}, JOURNAL)
            _config["audit"]("acteur-ban", f"id {ident} acteur {acteur} posees {len(poses)} refusees {len(refuses)}", user)
        except Exception:  # noqa: BLE001 — un ban hors journal ou non audité n'existe pas : il est retiré
            if poses and not _retirer(poses, fin):
                raise HTTPException(500, detail={"motif": "incoherent"}) from None    # reste visible et levable
            _abandonner(ident, "audit", maintenant)
            raise HTTPException(503, detail={"motif": "audit"}) from None
    _config["apres"]()
    return {"id": ident, "acteur": acteur, "posees": len(poses), "presentes": len(_liste(doc, "presents", cibles)),
            "refusees": [{"ip": ip, "motif": str(refuses[ip])[:32]} for ip in cibles if ip in refuses], "fin": fin}


def _abandonner(ident: str, cause: str, maintenant: int) -> None:
    try:
        _clore(ident, cause, maintenant)
    except OSError:
        log.error("acteurs : abandon %s non journalisé", ident)


@router.post("/gestes/{ident}/lever")
def lever(ident: str, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    if not _RE_ID.fullmatch(ident):
        raise HTTPException(404, detail={"motif": "inconnu"})
    with _verrou:
        maintenant = int(time.time())
        geste = next((g for g in _gestes_actifs(_lire_journal(), maintenant) if g["id"] == ident), None)
        if geste is None:
            raise HTTPException(404, detail={"motif": "inconnu"})
        cibles = [ip for ip in geste["cibles"] if isinstance(ip, str)]
        try:
            _config["audit"]("acteur-lever-demande", f"id {ident} acteur {geste['acteur']} {len(cibles)} adresses", user)
        except Exception:  # noqa: BLE001
            raise HTTPException(503, detail={"motif": "audit"}) from None
        couvertes = _couvertes_par_le_waf(cibles, maintenant)
        libres = [ip for ip in cibles if ip not in couvertes]
        doc: dict = {}
        if libres:
            try:
                doc = _executer("unban-lot", [str(geste["fin"])] + (["incertain"] if geste["incertain"] else []), libres)
            except Incertain:
                raise HTTPException(503, detail={"motif": "wafctl"}) from None
        leves, absents = _liste(doc, "leves", libres), _liste(doc, "absents", libres)
        restantes = [ip for ip in cibles if ip not in leves and ip not in absents]
        try:
            _clore(ident, "lever", maintenant, cibles=leves + absents, par=_qui(user))
            _config["audit"]("acteur-lever", f"id {ident} levees {len(leves)} gardees {len(restantes)}", user)
        except Exception as e:  # noqa: BLE001 — la levée est faite : dite incertaine, pas défaite
            log.error("acteurs : levée %s mal tracée : %s", ident, e)
            raise HTTPException(500, detail={"motif": "incoherent"}) from None
    _config["apres"]()
    return {"id": ident, "levees": len(leves), "gardees": len(restantes)}

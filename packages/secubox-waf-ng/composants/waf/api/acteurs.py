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
- `POST /acteurs/gestes/{id}/lever` : retire les seules adresses posées par ce geste (`wafctl unban-lot` refuse celles
  dont un autre a allongé le ban).

Épargnées : forme ou plage non publique, liste blanche, liste blanche SADE, pair du maillage, adresse d'une session
ouverte ou du demandeur, robot vérifié, robot non vérifiable (DNS en doute). Une source de protection illisible refuse
le geste (503). Audit avant et après ; sans journal ou audit, le lot posé est retiré.
"""
from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
import json
import logging
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt

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
    """Adresses des sessions ouvertes. Absent : aucune ; illisible : ProtectionInconnue."""
    try:
        doc = json.loads(SESSIONS.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        raise _g.ProtectionInconnue(f"sessions : {type(e).__name__}") from None
    if isinstance(doc, dict):
        doc = list(doc.values())
    if not isinstance(doc, list):
        raise _g.ProtectionInconnue("sessions : forme inattendue")
    return [n for s in doc if isinstance(s, dict) for n in [_g._reseau_pair(s.get("ip"))] if n is not None]


def _protections(demandeur: str) -> List[Tuple[str, List[Any]]]:
    """[(motif, réseaux)] ; toute source illisible refuse le geste."""
    try:
        sade = _g.lire_sade()
        return [("liste_blanche", [n for n in map(_g._reseau_pair, _config["liste_blanche"]()) if n is not None]),
                ("sade", list(sade["liste"]) if sade else []),
                ("pair", _g.pairs_wg_mesh() + _g.pairs_threatmesh()),
                ("session", _reseaux_sessions() + [n for n in [_g._reseau_pair(demandeur)] if n is not None])]
    except (_g.ProtectionInconnue, _g.Illisible, OSError, KeyError, TypeError, AttributeError) as e:
        log.warning("acteurs : protection illisible : %s", e)
        raise HTTPException(503, detail={"motif": "protegee_inconnue"}) from None


def _motif_epargne(ip: str, protections: List[Tuple[str, List[Any]]]) -> Optional[str]:
    try:
        a = _gb.adresse_publique(ip)
    except ValueError as e:
        return str(e)
    return next((motif for motif, reseaux in protections if any(_g._touche(a, n) for n in reseaux)), None)


def _robots(ips: List[str]) -> Dict[str, str]:
    """{adresse: motif} des robots vérifiés et des adresses dont le DNS n'a pas répondu (le doute épargne)."""
    taches = {_dns.submit(_g._fcrdns, ip): ip for ip in ips}
    finies, _ = concurrent.futures.wait(taches, timeout=_DELAI_DNS_LOT_S)
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


def _demandeur(request: Request) -> str:
    """Adresse du poste de l'administrateur, posée par nginx ; à défaut celle de la connexion."""
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def _qui(user: Any) -> str:
    return str((user or {}).get("sub") or "")


def _lire_journal() -> List[dict]:
    try:
        lignes = _g._lire_fin_jsonl(JOURNAL, _g._TAILLE_LECTURE) or []
    except OSError:
        raise HTTPException(503, detail={"motif": "journal"}) from None
    return [e for e in lignes if isinstance(e, dict) and isinstance(e.get("id"), str) and _RE_ID.fullmatch(e["id"])
            and _g._entier(e.get("at"))
            and (e.get("type") == "leve" or e.get("type") == "ban" and isinstance(e.get("cibles"), list)
                 and _g._entier(e.get("fin")) and isinstance(e.get("acteur"), str))]


def _gestes_actifs(entrees: List[dict], maintenant: int) -> List[dict]:
    leves = {e["id"] for e in entrees if e["type"] == "leve"}
    return [e for e in entrees if e["type"] == "ban" and e["id"] not in leves and e["fin"] > maintenant]


def _executer(verbe: str, argument: str, ips: List[str]) -> dict:
    """`sudo wafctl <verbe> <argument>`, adresses sur l'entrée standard. Le document JSON rendu, ou 503 `wafctl`."""
    try:
        r = subprocess.run(["sudo", "-n", _g.WAFCTL, verbe, argument], input="\n".join(ips) + "\n", check=False,
                           timeout=60, capture_output=True, text=True)
        doc = json.loads(r.stdout) if r.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        log.error("acteurs : wafctl %s : %s", verbe, type(e).__name__)
        doc = None
    if not isinstance(doc, dict):
        raise HTTPException(503, detail={"motif": "wafctl"})
    return doc


def _liste(doc: dict, cle: str, permises: List[str]) -> List[str]:
    v = doc.get(cle)
    return [ip for ip in permises if isinstance(v, list) and ip in v]


def _retirer(ips: List[str], fin: int) -> bool:
    try:
        _executer("unban-lot", str(fin), ips)
        return True
    except HTTPException:
        log.error("acteurs : retour arrière impossible (%d adresses)", len(ips))
        return False


@router.get("/{acteur}/etat")
def etat(acteur: str, _user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    maintenant = int(time.time())
    vues, partiel = _adresses(acteur, maintenant)
    bannies = _bannies()
    actifs = [g for g in _gestes_actifs(_lire_journal(), maintenant) if g["acteur"] == acteur]
    return {"acteur": acteur, "vues_48h": len(vues), "bannies": sum(ip in bannies for ip, _ in vues), "partiel": partiel,
            "gestes": [{"id": g["id"], "at": g["at"], "fin": g["fin"], "nombre": len(g["cibles"]),
                        "par": str(g.get("par") or "")} for g in actifs]}


@router.get("/{acteur}/apercu")
def apercu(acteur: str, request: Request, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    maintenant = int(time.time())
    vues, partiel = _adresses(acteur, maintenant)
    bannies, protections = _bannies(), _protections(_demandeur(request))
    deja, epargnees, candidates = [], [], []
    for ip, vu in vues:
        motif = _motif_epargne(ip, protections)
        if motif:
            epargnees.append({"ip": ip, "motif": motif})
        elif ip in bannies:
            deja.append(ip)
        else:
            candidates.append((ip, vu))
    retenues, reste = candidates[:MAX_ADRESSES], max(0, len(candidates) - MAX_ADRESSES)
    robots = _robots([ip for ip, _ in retenues])
    epargnees += [{"ip": ip, "motif": m} for ip, m in robots.items()]
    a_bannir = [{"ip": ip, "vu": vu} for ip, vu in retenues if ip not in robots]
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
        if sum(e["type"] == "ban" and maintenant - e["at"] < 3600 for e in _lire_journal()) >= PLAFOND_HEURE:
            raise HTTPException(409, detail={"motif": "plafond"})
        protections = _protections(_demandeur(request))
        cibles = [ip for ip in ap["ips"] if _motif_epargne(ip, protections) is None]
        if not cibles:
            raise HTTPException(409, detail={"motif": "vide"})
        del _apercus[demande.apercu]                       # usage unique, quel que soit le résultat
        ident = secrets.token_hex(16)
        try:
            _config["audit"]("acteur-ban-demande", f"id {ident} acteur {acteur} {len(cibles)} adresses {DUREE_S}s", user)
        except Exception:  # noqa: BLE001 — sans trace de la demande, rien n'est fait
            raise HTTPException(503, detail={"motif": "audit"}) from None
        try:
            doc = _executer("ban-lot", f"{DUREE_S}s", cibles)
        except HTTPException:
            _retirer(cibles, int(time.time()) + DUREE_S)   # wafctl muet : peut-être posé
            raise
        fin = int(time.time()) + DUREE_S
        poses = _liste(doc, "poses", cibles)
        refuses = doc["refuses"] if isinstance(doc.get("refuses"), dict) else {}
        if poses:
            try:
                _gb._ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "ban", "id": ident, "acteur": acteur,
                                     "cibles": poses, "fin": fin, "par": _qui(user)}, JOURNAL)
                _config["audit"]("acteur-ban", f"id {ident} acteur {acteur} posees {len(poses)} refusees {len(refuses)}", user)
            except Exception:  # noqa: BLE001 — un ban hors journal ou non audité n'existe pas : il est retiré
                defait = _retirer(poses, fin)
                try:
                    _gb._ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "leve", "id": ident,
                                         "cause": "audit"}, JOURNAL)
                except OSError:
                    log.error("acteurs : annulation %s non journalisée", ident)
                raise HTTPException(503 if defait else 500, detail={"motif": "audit" if defait else "incoherent"}) from None
    _config["apres"]()
    return {"id": ident, "acteur": acteur, "posees": len(poses), "presentes": len(_liste(doc, "presents", cibles)),
            "refusees": [{"ip": ip, "motif": str(refuses[ip])[:32]} for ip in cibles if ip in refuses], "fin": fin}


@router.post("/gestes/{ident}/lever")
def lever(ident: str, user: dict = Depends(require_jwt)) -> Dict[str, Any]:
    if not _RE_ID.fullmatch(ident):
        raise HTTPException(404, detail={"motif": "inconnu"})
    with _verrou:
        maintenant = int(time.time())
        geste = next((g for g in _gestes_actifs(_lire_journal(), maintenant) if g["id"] == ident), None)
        if geste is None:
            raise HTTPException(404, detail={"motif": "inconnu"})
        cibles = [ip for ip in geste["cibles"] if isinstance(ip, str) and _adresse_ou_rien(ip)]
        try:
            _config["audit"]("acteur-lever-demande", f"id {ident} acteur {geste['acteur']} {len(cibles)} adresses", user)
        except Exception:  # noqa: BLE001
            raise HTTPException(503, detail={"motif": "audit"}) from None
        doc = _executer("unban-lot", str(geste["fin"]), cibles)
        leves, couverts = _liste(doc, "leves", cibles), _liste(doc, "couverts", cibles)
        try:
            _gb._ecrire_journal({"ts": _g._horodatage(), "at": maintenant, "type": "leve", "id": ident, "cause": "lever",
                                 "par": _qui(user)}, JOURNAL)
            _config["audit"]("acteur-lever", f"id {ident} levees {len(leves)} gardees {len(couverts)}", user)
        except Exception as e:  # noqa: BLE001 — la levée est faite : elle est dite, pas défaite
            log.error("acteurs : levée %s mal tracée : %s", ident, e)
    _config["apres"]()
    return {"id": ident, "levees": len(leves), "gardees": len(couverts)}


def _adresse_ou_rien(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes `/adblock-tv/*` du POC « DNS AdBlock TV » (#1943).

Lecture : `require_lecture`. Toute action (modes, appareils, liste personnalisée) : `require_jwt` (administrateur). L'API n'écrit JAMAIS
dans Unbound : elle écrit l'état (fichier JSON validé) puis demande au contrôleur root `secubox-adguard-tv apply` — qui relit et revalide.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt, require_lecture

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv

router = APIRouter(prefix="/adblock-tv", tags=["adblock-tv"])
CTL = os.environ.get("SECUBOX_ADGUARD_TV_CTL", "/usr/sbin/secubox-adguard-tv")
CUSTOM_MAX = 2000
SONDE_ZONE = "sbx-dnspath.invalid"          # `.invalid` : jamais résolu hors de la box ; seule sa ligne de journal nous importe


def _ctl(action: str) -> dict:
    """Le contrôleur root (sudo, argv exact). Un échec rend 502 avec son message court, jamais une trace."""
    argv = ["sudo", "-n", CTL, action] if os.geteuid() != 0 else [CTL, action]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HTTPException(502, f"contrôleur injoignable ({type(e).__name__})") from e
    if r.returncode != 0:
        raise HTTPException(502, ((r.stderr or r.stdout).strip() or "contrôleur en échec")[:300])
    try:
        return json.loads(r.stdout or "{}")
    except ValueError:
        return {}


def _magasin() -> dnstv.Magasin:
    return dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db")


def _etat() -> dict:
    etat, erreur = dnstv.lire_etat()
    if erreur:
        raise HTTPException(409, erreur)
    return etat


def _perso_path():
    return dnstv.DOSSIER_ETAT / "custom.txt"


def _table() -> dict:
    p = _perso_path()
    return dnstv.charger_listes(dnstv.DOSSIER_LISTES, p if p.is_file() else None)


class EtatIn(BaseModel):
    actif: bool


class ClientIn(BaseModel):
    ip: str = Field(min_length=2, max_length=45)
    nom: str = Field(default="", max_length=40)
    mode: str = "observe"


class ModeIn(BaseModel):
    mode: str
    ip: Optional[str] = Field(default=None, max_length=45)


class DomaineIn(BaseModel):
    domaine: str = Field(min_length=3, max_length=253)


def _refuse(e: dnstv.ErreurTV):
    raise HTTPException(422, str(e))


@router.get("/status", dependencies=[Depends(require_lecture)])
async def statut():
    etat, erreur = dnstv.lire_etat()
    table = _table()
    stats = _magasin().statistiques()
    return {"actif": etat["actif"], "clients": etat["clients"], "erreur": erreur, "dropin_present": dnstv.CONF_UNBOUND.is_file(),
            "listes": {"domaines": len(table), "problemes": dnstv.verifier_manifeste(dnstv.DOSSIER_LISTES),
                       "par_categorie": {c: sum(1 for v in table.values() if v == c) for c in dnstv.CATEGORIES}},
            "compteurs": {"requetes": stats["requetes"], "domaines_uniques": stats["domaines_uniques"],
                          "bloques": stats["par_decision"].get("BLOCKED", 0)}}


@router.post("/etat", dependencies=[Depends(require_jwt)])
async def activer(corps: EtatIn):
    etat = _etat()
    etat["actif"] = corps.actif
    dnstv.ecrire_etat(etat)
    return {"etat": etat, "application": _ctl("apply")}


@router.post("/clients", dependencies=[Depends(require_jwt)])
async def declarer_client(c: ClientIn):
    etat = _etat()
    try:
        ip = dnstv._ip(c.ip)
        etat["clients"] = [x for x in etat["clients"] if x["ip"] != ip] + [{"ip": ip, "nom": c.nom or ip, "mode": c.mode}]
        dnstv.ecrire_etat(etat)
    except dnstv.ErreurTV as e:
        _refuse(e)
    return {"etat": etat, "application": _ctl("apply")}


@router.delete("/clients/{ip}", dependencies=[Depends(require_jwt)])
async def retirer_client(ip: str):
    etat = _etat()
    try:
        cible = dnstv._ip(ip)
    except dnstv.ErreurTV as e:
        _refuse(e)
    avant = len(etat["clients"])
    etat["clients"] = [x for x in etat["clients"] if x["ip"] != cible]
    if len(etat["clients"]) == avant:
        raise HTTPException(404, "appareil inconnu")
    dnstv.ecrire_etat(etat)
    return {"etat": etat, "application": _ctl("apply")}


@router.post("/mode", dependencies=[Depends(require_jwt)])
async def changer_mode(m: ModeIn):
    """Bascule dynamique OBSERVE / BLOCK (ou off) : un appareil, ou tous ceux du périmètre."""
    if m.mode not in dnstv.MODES:
        raise HTTPException(422, "mode inconnu (off, observe, block)")
    etat = _etat()
    try:
        cible = dnstv._ip(m.ip) if m.ip else None
    except dnstv.ErreurTV as e:
        _refuse(e)
    touches = 0
    for c in etat["clients"]:
        if cible is None or c["ip"] == cible:
            c["mode"] = m.mode
            touches += 1
    if not touches:
        raise HTTPException(404, "aucun appareil concerné")
    dnstv.ecrire_etat(etat)
    return {"etat": etat, "application": _ctl("apply")}


@router.get("/stats", dependencies=[Depends(require_lecture)])
async def statistiques(client: Optional[str] = None, jours: int = 7, limite: int = 20):
    if client:
        try:
            client = dnstv._ip(client)
        except dnstv.ErreurTV as e:
            _refuse(e)
    depuis = time.strftime("%Y-%m-%d", time.gmtime(time.time() - max(1, min(jours, 365)) * 86400))
    m = _magasin()
    s = m.statistiques(client, depuis)
    return {"jours": jours, "client": client, **s,
            "top_bloques": m.top("BLOCKED", limite, client),
            "top_resolus_classes": [t for t in m.top("ALLOWED", 200, client) if t["categorie"]][:limite],
            "formulation": "réduction des domaines publicitaires/tracking résolus par DNS (ce n'est pas une suppression de publicités)"}


@router.get("/export", dependencies=[Depends(require_lecture)])
async def exporter(client: Optional[str] = None, jours: int = 2):
    """Relevé complet des compteurs d'un appareil (domaine, catégorie, décision, hits) : sert à comparer deux instants (phases A/B/C)."""
    if client:
        try:
            client = dnstv._ip(client)
        except dnstv.ErreurTV as e:
            _refuse(e)
    depuis = time.strftime("%Y-%m-%d", time.gmtime(time.time() - max(1, min(jours, 30)) * 86400))
    return {"client": client, "releve": int(time.time()), "lignes": _magasin().lignes(client, depuis)}


@router.get("/clients/vus", dependencies=[Depends(require_lecture)])
async def clients_vus():
    return {"clients": _magasin().par_client()}


@router.get("/custom", dependencies=[Depends(require_lecture)])
async def lire_custom():
    p = _perso_path()
    return {"domaines": sorted(dnstv.lire_liste(p)[0]) if p.is_file() else []}


@router.post("/custom", dependencies=[Depends(require_jwt)])
async def ajouter_custom(d: DomaineIn):
    dom = dnstv.valider_domaine(d.domaine)
    if not dom:
        raise HTTPException(422, "nom de domaine invalide")
    p = _perso_path()
    courants = set(dnstv.lire_liste(p)[0]) if p.is_file() else set()
    if len(courants) >= CUSTOM_MAX and dom not in courants:
        raise HTTPException(422, f"{CUSTOM_MAX} domaines au plus")
    courants.add(dom)
    dnstv.DOSSIER_ETAT.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text("# liste personnalisée (POC DNS AdBlock TV)\n" + "".join(x + "\n" for x in sorted(courants)), encoding="utf-8")
    os.replace(tmp, p)
    return {"domaine": dom, "total": len(courants), "application": _ctl("apply")}


@router.delete("/custom/{domaine}", dependencies=[Depends(require_jwt)])
async def retirer_custom(domaine: str):
    dom = dnstv.valider_domaine(domaine)
    p = _perso_path()
    if not dom or not p.is_file() or dom not in dnstv.lire_liste(p)[0]:
        raise HTTPException(404, "domaine inconnu")
    restants = sorted(set(dnstv.lire_liste(p)[0]) - {dom})
    tmp = p.with_suffix(".tmp")
    tmp.write_text("# liste personnalisée (POC DNS AdBlock TV)\n" + "".join(x + "\n" for x in restants), encoding="utf-8")
    os.replace(tmp, p)
    return {"retire": dom, "total": len(restants), "application": _ctl("apply")}


# ── DNS PATH TEST ────────────────────────────────────────────────────────────
@router.post("/sonde", dependencies=[Depends(require_jwt)])
async def sonde():
    """Un nom unique à interroger DEPUIS l'appareil testé (ou la machine cliente) ; `/path-test` dit alors si la box l'a reçu."""
    return {"nom": f"t{uuid.uuid4().hex[:10]}.{SONDE_ZONE}",
            "consigne": "interrogez ce nom depuis l'appareil (ex. dns-tv-test.py <nom> --serveur <IP de la box>), puis appelez /path-test"}


@router.get("/path-test", dependencies=[Depends(require_lecture)])
async def path_test(nom: Optional[str] = None, ip: Optional[str] = None, secondes: int = 300):
    """client → DNS demandé → SecuBox reçue ? → domaine → décision → amont."""
    if nom is None and ip is None:
        raise HTTPException(422, "donnez le nom de la sonde ou l'adresse de l'appareil")
    if nom is not None and not (nom.endswith("." + SONDE_ZONE) and dnstv.valider_domaine(nom)):
        raise HTTPException(422, "nom de sonde invalide")
    depuis = int(time.time()) - max(10, min(secondes, 86400))
    m = _magasin()
    trouve: List[dict] = []
    clients = [dnstv._ip(ip)] if ip else [c["client"] for c in m.par_client()]
    for c in clients:
        for e in m.evenements_recents(c, depuis):
            if (nom is None) or e["domaine"] == nom:
                trouve.append({"client": c, **e})
    etat, _ = dnstv.lire_etat()
    return {"recue": bool(trouve), "evenements": trouve[:50], "periode_s": secondes,
            "amont": "résolveur récursif Unbound de la box (voir /etc/unbound)",
            "lecture": ("la box a reçu cette requête : le client utilise bien son DNS" if trouve else
                        "AUCUNE requête reçue : le client utilise un autre résolveur (DNS de la Freebox, IPv6, DoH/DoT…) — ou la sonde n'a pas encore été posée"),
            "mode_du_client": next((c["mode"] for c in etat["clients"] if ip and c["ip"] == dnstv._ip(ip)), None)}


@router.get("/bypass", dependencies=[Depends(require_lecture)])
async def contournement(minutes: int = 60):
    """Appareils visibles sur le réseau (ARP/NDP) mais SILENCIEUX côté DNS de la box : candidats au contournement. Sans aucune inspection
    de trafic : on compare deux listes. Limite honnête : la box ne voit pas un DNS externe qui ne passe pas par elle."""
    vus = {c["client"]: c for c in _magasin().par_client()}
    limite = int(time.time()) - max(1, min(minutes, 1440)) * 60
    actifs = {ip for ip, c in vus.items() if c["derniere_vue"] >= limite}
    voisins = []
    try:
        r = subprocess.run(["ip", "-j", "neigh"], capture_output=True, text=True, timeout=10)
        for n in json.loads(r.stdout or "[]"):
            if n.get("state") and set(n["state"]) & {"REACHABLE", "STALE", "DELAY", "PROBE"} and n.get("dst") and n.get("lladdr"):
                voisins.append({"ip": n["dst"], "mac": n["lladdr"]})
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    silencieux = [v for v in voisins if v["ip"] not in actifs and not v["ip"].startswith("fe80")]
    return {"minutes": minutes, "voisins": voisins, "clients_dns_actifs": sorted(actifs), "silencieux": silencieux,
            "limite": "un appareil silencieux peut simplement ne rien résoudre ; un DNS externe n'est visible que s'il passe par la box"}


# ── visualisation : flux en direct, sources, séries, services ────────────────────────────────────────────────────────────
_CACHE: dict = {"voisins": (0.0, {}), "noms": {}, "services": (0.0, None)}


def _voisins() -> dict:
    t, v = _CACHE["voisins"]
    if time.time() - t > 20:
        v = dnstv.lire_voisins()
        _CACHE["voisins"] = (time.time(), v)
    return v


def _services() -> dnstv.ClasseurServices:
    t, c = _CACHE["services"]
    if c is None or time.time() - t > 300:
        f = dnstv.DOSSIER_LISTES / "services.txt"
        c = dnstv.ClasseurServices(dnstv.charger_services(f) if f.is_file() else [])
        _CACHE["services"] = (time.time(), c)
    return c


def _passerelle() -> Optional[str]:
    try:
        r = subprocess.run(["ip", "-j", "route", "show", "default"], capture_output=True, text=True, timeout=5)
        return json.loads(r.stdout or "[]")[0].get("gateway")
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def _nom_pour(ips: List[str], declares: dict) -> str:
    """Nom lisible d'une source : celui déclaré dans le POC, sinon le nom que le routeur du réseau lui donne (DNS inverse, mis en cache 1 h)."""
    for ip in ips:
        if ip in declares:
            return declares[ip]
    gw = _passerelle()
    for ip in ips:
        if ":" in ip or not gw or not ip.startswith(("192.168.", "10.", "172.")):
            continue
        t, n = _CACHE["noms"].get(ip, (0.0, None))
        if n is None or time.time() - t > 3600:
            try:
                r = subprocess.run(["dig", "+short", "+time=2", "+tries=1", "-x", ip, f"@{gw}"], capture_output=True, text=True, timeout=5)
                n = (r.stdout.split("\n")[0] or "").rstrip(".")
            except (OSError, subprocess.TimeoutExpired):
                n = ""
            _CACHE["noms"][ip] = (time.time(), n)
        if n:
            return n
    return ""


def _sources() -> dict:
    """clé (MAC ou adresse) -> {ips, nom}. Les adresses IPv4 et IPv6 d'un même appareil forment UNE source."""
    declares = {c["ip"]: c["nom"] for c in dnstv.lire_etat()[0]["clients"]}
    groupes = dnstv.regrouper_sources([c["client"] for c in _magasin().par_client()], _voisins())
    return {k: {"ips": ips, "nom": _nom_pour(ips, declares)} for k, ips in groupes.items()}


def _ips_de(source: Optional[str]) -> Optional[List[str]]:
    if not source:
        return None
    src = _sources()
    cle = source.lower()
    if cle in src:
        return src[cle]["ips"]
    try:
        ip = dnstv._ip(source)
    except dnstv.ErreurTV as e:
        raise HTTPException(422, "source inconnue (adresse MAC ou IP attendue)") from e
    for v in src.values():                                               # une adresse : toute sa source
        if ip in v["ips"]:
            return v["ips"]
    return [ip]


def _etiqueter(lignes: List[dict]) -> List[dict]:
    cl = _services()
    for x in lignes:
        x["service"], x["type"] = cl.classer(x["domaine"])
    return lignes


@router.get("/sources", dependencies=[Depends(require_lecture)])
async def sources(heures: int = 24):
    """Une ligne par APPAREIL : requêtes, blocages, taux, domaines uniques, répartition par type de service."""
    depuis = int(time.time()) - max(1, min(heures, 48)) * 3600
    m = _magasin()
    out = []
    for cle, v in _sources().items():
        fl = _etiqueter(m.flux(v["ips"], depuis))
        if not fl:
            continue
        req = sum(x["requetes"] for x in fl)
        blq = sum(x["bloquees"] or 0 for x in fl)
        par_type: dict = {}
        for x in fl:
            par_type[x["type"]] = par_type.get(x["type"], 0) + x["requetes"]
        out.append({"source": cle, "nom": v["nom"], "adresses": v["ips"], "requetes": req, "bloquees": blq,
                    "taux_blocage": round(blq / req, 3) if req else 0.0, "domaines_uniques": len(fl), "par_type": par_type,
                    "derniere": max(x["derniere"] for x in fl)})
    out.sort(key=lambda x: -x["requetes"])
    return {"heures": heures, "sources": out,
            "limite": "le DNS montre les NOMS demandés, pas les volumes ni le contenu ; un appareil qui n'interroge pas cette box n'apparaît pas"}


@router.get("/live", dependencies=[Depends(require_lecture)])
async def en_direct(source: Optional[str] = None, secondes: int = 120, limite: int = 60):
    """Les dernières requêtes (flux en cours), la plus récente d'abord, avec le service et le type de chaque nom."""
    depuis = int(time.time()) - max(5, min(secondes, 3600))
    ips = _ips_de(source)
    lignes = _magasin().recents(ips, depuis, limite)
    cl = _services()
    for x in lignes:
        x["service"], x["type"] = cl.classer(x["domaine"])
    return {"maintenant": int(time.time()), "source": source, "evenements": lignes}


@router.get("/serie", dependencies=[Depends(require_lecture)])
async def serie(source: Optional[str] = None, heures: int = 6, pas: int = 300):
    depuis = int(time.time()) - max(1, min(heures, 48)) * 3600
    return {"pas_s": pas, "points": _magasin().serie(_ips_de(source), depuis, pas)}


@router.get("/flux", dependencies=[Depends(require_lecture)])
async def flux(source: Optional[str] = None, heures: int = 6):
    """L'« équivalent DPI » : par nom de domaine, avec service, type et décisions ; plus la synthèse par service."""
    depuis = int(time.time()) - max(1, min(heures, 48)) * 3600
    lignes = _etiqueter(_magasin().flux(_ips_de(source), depuis))
    par_service: dict = {}
    for x in lignes:
        k = (x["service"] or "(inconnu)", x["type"])
        d = par_service.setdefault(k, {"service": k[0], "type": k[1], "requetes": 0, "bloquees": 0, "domaines": 0})
        d["requetes"] += x["requetes"]
        d["bloquees"] += x["bloquees"] or 0
        d["domaines"] += 1
    return {"heures": heures, "source": source, "domaines": lignes,
            "services": sorted(par_service.values(), key=lambda d: -d["requetes"]),
            "limite": "pas de volumes (octets) : le DNS ne les voit pas ; un vrai DPI ne verrait ces flux que s'ils traversaient la box"}


@router.get("/limites", dependencies=[Depends(require_lecture)])
async def limites():
    return {"limites": LIMITES}


LIMITES = [
    {"id": "A", "cas": "publicité servie depuis un domaine publicitaire distinct", "dns": "bloquable"},
    {"id": "B", "cas": "tracking servi depuis un domaine distinct", "dns": "bloquable"},
    {"id": "C", "cas": "publicité et vidéo servies depuis le MÊME domaine", "dns": "insuffisant : bloquer le nom casse aussi la vidéo"},
    {"id": "D", "cas": "publicité intégrée directement dans le flux vidéo", "dns": "insuffisant : aucun nom distinct à bloquer"},
    {"id": "E", "cas": "application utilisant des adresses IP codées en dur", "dns": "contourné : aucune requête DNS n'est émise"},
    {"id": "F", "cas": "DoH / DoT côté client", "dns": "contourné : la box ne voit pas les requêtes"},
    {"id": "G", "cas": "domaine partagé entre contenu légitime et publicité", "dns": "faux positifs : bloquer l'un bloque l'autre"},
]

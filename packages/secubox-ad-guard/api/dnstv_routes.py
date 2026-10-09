# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes `/adblock-tv/*` du POC « DNS AdBlock TV » (#1943).

Lecture : `require_lecture`. Toute action (modes, appareils, liste personnalisée) : `require_jwt` (administrateur). L'API n'écrit JAMAIS
dans Unbound : elle écrit l'état (fichier JSON validé) puis demande au contrôleur root `secubox-adguard-tv apply` — qui relit et revalide.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt, require_lecture

try:
    from . import dnstv, dnstv_ajout, dnstv_auto, dnstv_dnsbox, dnstv_profil, dnstv_regles, dnstv_simple
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_ajout, dnstv_auto, dnstv_dnsbox, dnstv_profil, dnstv_regles, dnstv_simple

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
    mode: str = "auto"                               # auto par défaut (#2174) : un appareil déclaré est protégé sans autre geste


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


# Les routes qui écrivent l'état sont SYNCHRONES et prennent le verrou commun avec le moteur (revue #1959) : une action de l'administrateur n'est jamais
# écrasée par un passage de la minuterie qui aurait lu l'état avant elle, et le sudo du contrôleur ne gèle pas la boucle du groupe.
@router.post("/etat", dependencies=[Depends(require_jwt)])
def activer(corps: EtatIn):
    with _verrou():
        etat = _etat()
        etat["actif"] = corps.actif
        dnstv.ecrire_etat(etat)
        return {"etat": etat, "application": _ctl("apply")}


@router.post("/clients", dependencies=[Depends(require_jwt)])
def declarer_client(c: ClientIn):
    with _verrou():
        etat = _etat()
        try:
            ip = dnstv._ip(c.ip)
            etat["clients"] = [x for x in etat["clients"] if x["ip"] != ip] + [{"ip": ip, "nom": c.nom or ip, "mode": c.mode}]
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        return {"etat": etat, "application": _ctl("apply")}


@router.delete("/clients/{ip}", dependencies=[Depends(require_jwt)])
def retirer_client(ip: str):
    with _verrou():
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
def changer_mode(m: ModeIn):
    """Bascule dynamique OBSERVE / BLOCK (ou off) : un appareil, ou tous ceux du périmètre."""
    if m.mode not in dnstv.MODES:
        raise HTTPException(422, "mode inconnu (off, observe, block, auto)")
    with _verrou():
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
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
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


# ── mode « auto » (#1954) : règles apprises, essai, confirmation, retour arrière ──────────────────────────────────────────
ACTIONS_REGLE = {"essayer": ("essai", {"candidat", "retire"}), "confirmer": ("confirme", {"essai"}),
                 "rejeter": ("rejete", {"candidat", "retire"}), "retirer": ("retire", {"essai", "confirme", "candidat"}),
                 "rouvrir": ("candidat", {"rejete"})}


class AutoEssaiIn(BaseModel):
    actif: bool


def _verrou():
    try:
        return dnstv_regles.verrou()
    except OSError as e:
        raise HTTPException(503, f"verrou des règles indisponible ({type(e).__name__})") from e


def _regles() -> "dnstv_regles.Regles":
    try:
        return dnstv_regles.charger()
    except dnstv_regles.ErreurRegle as e:
        raise HTTPException(409, str(e)) from e


@router.get("/auto/regles", dependencies=[Depends(require_lecture)])
def regles_liste(etat: Optional[str] = None, appareil: Optional[str] = None):
    toutes = _regles().liste()
    compteurs: dict = {}
    for r in toutes:
        compteurs[r["etat"]] = compteurs.get(r["etat"], 0) + 1
    sel = [r for r in toutes if (not etat or r["etat"] == etat) and (not appareil or r["appareil"] == appareil)]
    return {"regles": sel, "compteurs": compteurs}


def _appliquer_ou_annuler(ancien: "dnstv_regles.Regles") -> dict:
    """Demande l'application au contrôleur root ; s'il échoue, `regles.json` revient à son état précédent : l'interface ne ment pas."""
    try:
        return _ctl("regles-appliquer")
    except HTTPException:
        dnstv_regles.ecrire(ancien)
        raise


# Les routes qui appellent le contrôleur sont SYNCHRONES (`def`) : FastAPI les exécute dans un fil, la boucle du groupe n'est pas gelée
# pendant un sudo ou un éventuel rechargement complet d'Unbound.
@router.post("/auto/regles/{rid}/{action}", dependencies=[Depends(require_jwt)])
def regle_action(rid: str, action: str):
    if action not in ACTIONS_REGLE or not re.fullmatch(r"[0-9a-f]{12}", rid):
        raise HTTPException(404, "action ou règle inconnue")
    vers, depuis = ACTIONS_REGLE[action]
    with _verrou():
        regles, ancien = _regles(), _regles()
        try:
            avant = regles.get(rid)["etat"]
        except dnstv_regles.ErreurRegle:
            raise HTTPException(404, "règle inconnue") from None
        if avant not in depuis:
            raise HTTPException(422, f"action impossible depuis l'état « {avant} »")
        try:
            r = regles.transiter(rid, vers, "admin", f"action {action}", int(time.time()))
        except dnstv_regles.ErreurRegle as e:
            raise HTTPException(422, str(e)) from e
        dnstv_regles.ecrire(regles)
        return {"regle": r, "application": _appliquer_ou_annuler(ancien)}     # toujours : le contrôleur audite chaque transition effective


@router.post("/auto/appareils/{appareil}/ca-ne-marche-plus", dependencies=[Depends(require_jwt)])
def ca_ne_marche_plus(appareil: str):
    """Retour arrière d'un geste : retire TOUTES les règles en essai de cet appareil (les confirmées restent)."""
    with _verrou():
        regles, ancien = _regles(), _regles()
        touches = [r for r in regles.liste() if r["appareil"] == appareil and r["etat"] == "essai"]
        maintenant = int(time.time())
        for r in touches:
            regles.transiter(r["id"], "retire", "admin", "« ça ne marche plus »", maintenant)
        if not touches:
            return {"retirees": 0, "application": None}
        dnstv_regles.ecrire(regles)
        return {"retirees": len(touches), "application": _appliquer_ou_annuler(ancien)}


@router.get("/auto/reglage", dependencies=[Depends(require_lecture)])
def auto_reglage():
    etat = _etat()
    r = dnstv_auto.reglage_depuis(etat)
    return {"auto_essai": r.auto_essai, "declencheurs": list(r.declencheurs), "seuil_refus_min": r.seuil_refus_min,
            "duree_rafale_min": r.duree_rafale_min, "min_requetes_actif": r.min_requetes_actif,
            "appareils_auto": sorted(dnstv_auto.appareils(etat)), "essai_h": dnstv_regles.ESSAI_S // 3600}


@router.post("/auto/reglage/auto-essai", dependencies=[Depends(require_jwt)])
def auto_essai(corps: AutoEssaiIn):
    etat = _etat()
    avant = etat.get("auto_essai", False)
    etat["auto_essai"] = corps.actif
    dnstv.ecrire_etat(etat)
    try:
        application = _ctl("regles-appliquer")                                 # le contrôleur audite ce changement (décision de sécurité)
    except HTTPException:
        etat["auto_essai"] = avant
        dnstv.ecrire_etat(etat)
        raise
    return {"auto_essai": corps.actif, "application": application}


# ── fiche « DNS de la box » (#1938) : ce que la box offre aux appareils, en lecture seule ─────────────────────────────────────
def _sortie(argv: List[str]) -> str:
    """Sortie d'une commande de LECTURE (ip, ss), sans privilège ; vide si la commande manque ou échoue (la fiche le dit, elle ne plante pas)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout if r.returncode == 0 else ""


@router.get("/dns-box", dependencies=[Depends(require_lecture)])
def dns_box():
    return dnstv_dnsbox.dns_box(_sortie(["ip", "-6", "-o", "addr", "show", "scope", "global"]), _sortie(["ip", "-4", "-o", "addr", "show", "scope", "global"]),
                                _sortie(["ip", "-4", "route", "show", "default"]), _sortie(["ss", "-H", "-lnu"]))


# ── ajout automatique des TV et streamers, puits complet, profil agrégé (#1959) ───────────────────────────────────────────────
class ReglageDetectionIn(BaseModel):
    ajout_auto: Optional[bool] = None
    mode_defaut: Optional[str] = Field(default=None, max_length=10)


class PuitsIn(BaseModel):
    actif: bool


def _etat_et_copie():
    etat = _etat()
    return etat, copy.deepcopy(etat)


def _appliquer_ou_annuler_tout(ancien_etat: dict, ancien_regles: "dnstv_regles.Regles") -> dict:
    """Demande l'application au contrôleur ; s'il échoue, état ET règles reviennent à leur version précédente : l'interface ne ment pas."""
    try:
        return _ctl("regles-appliquer")
    except HTTPException:
        dnstv.ecrire_etat(ancien_etat)
        dnstv_regles.ecrire(ancien_regles)
        raise


def _clients_du_nom(etat: dict, nom: str) -> list:
    if not isinstance(nom, str) or not dnstv.NOM_RE.match(nom):
        raise HTTPException(404, "appareil inconnu")
    cs = [c for c in etat["clients"] if c["nom"] == nom]
    if not cs:
        raise HTTPException(404, "appareil inconnu")
    return cs


@router.get("/auto/detection", dependencies=[Depends(require_lecture)])
def detection():
    etat = _etat()
    par: dict = {}
    for c in etat["clients"]:
        a = par.setdefault(c["nom"], {"nom": c["nom"], "mode": c["mode"], "mac": c.get("mac", ""), "origine": c.get("origine", "admin"), "ajoute": c.get("ajoute", 0),
                                       "preuve": c.get("preuve", ""), "puits": c.get("puits", True), "adresses": []})
        a["adresses"].append(c["ip"])
    for a in par.values():
        a["autorisations"] = etat.get("autorisations", {}).get(dnstv_regles.slug(a["nom"]), [])
    suivi = dnstv_ajout.charger_suivi()
    reglage = dnstv_auto.reglage_depuis(etat)
    return {"ajout_auto": etat["ajout_auto"], "mode_defaut": etat["mode_defaut"], "ignores": etat["ignores"],
            "appareils": sorted(par.values(), key=lambda a: a["nom"]),
            "plafond": {"max_par_jour": reglage.max_par_jour, "ajouts_24h": len([x for x in suivi["ajouts"] if x > time.time() - 86400])}}


@router.post("/auto/detection/reglage", dependencies=[Depends(require_jwt)])
def detection_reglage(corps: ReglageDetectionIn):
    if corps.ajout_auto is None and corps.mode_defaut is None:
        raise HTTPException(422, "rien à régler (ajout_auto ou mode_defaut)")
    if corps.mode_defaut is not None and corps.mode_defaut not in dnstv.MODES_DEFAUT:
        raise HTTPException(422, "mode_defaut inconnu (off, observe, auto, block)")
    with _verrou():
        etat, ancien = _etat_et_copie()
        if corps.ajout_auto is not None:
            etat["ajout_auto"] = corps.ajout_auto
        if corps.mode_defaut is not None:
            etat["mode_defaut"] = corps.mode_defaut
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        try:
            application = _ctl("regles-appliquer")                        # le contrôleur audite ce changement (décision de sécurité)
        except HTTPException:
            dnstv.ecrire_etat(ancien)
            raise
        return {"ajout_auto": etat["ajout_auto"], "mode_defaut": etat["mode_defaut"], "application": application}


@router.post("/auto/appareils/{nom}/ignorer", dependencies=[Depends(require_jwt)])
def ignorer_appareil(nom: str):
    """Retire l'appareil du périmètre (retour au puits de production), ignore sa MAC et retire ses règles : plus jamais ajouté automatiquement."""
    with _verrou():
        etat, ancien_etat = _etat_et_copie()
        regles, ancien_regles = _regles(), _regles()
        cs = _clients_du_nom(etat, nom)
        macs = sorted({c["mac"] for c in cs if c.get("mac")})
        etat["clients"] = [c for c in etat["clients"] if c["nom"] != nom]
        for m in macs:
            if m not in etat["ignores"]:
                etat["ignores"].append(m)
        retirees = 0
        maintenant = int(time.time())
        for r in regles.liste():
            if r["appareil"] == dnstv_regles.slug(nom) and r["etat"] in ("candidat", "essai", "confirme"):
                regles.transiter(r["id"], "retire", "admin", "appareil retiré et ignoré", maintenant)
                retirees += 1
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        dnstv_regles.ecrire(regles)
        return {"retire": len(cs), "regles_retirees": retirees, "ignores": etat["ignores"], "application": _appliquer_ou_annuler_tout(ancien_etat, ancien_regles)}


@router.post("/auto/appareils/{nom}/puits", dependencies=[Depends(require_jwt)])
def puits_appareil(nom: str, corps: PuitsIn):
    """Puits de production complet (vrai, défaut) ou ancien comportement transparent (faux) pour un appareil en mode auto."""
    with _verrou():
        etat, ancien_etat = _etat_et_copie()
        cs = _clients_du_nom(etat, nom)
        if any(c["mode"] != "auto" for c in cs):
            raise HTTPException(422, "le réglage « puits » ne concerne que les appareils en mode auto")
        for c in cs:
            if corps.actif:
                c.pop("puits", None)
            else:
                c["puits"] = False
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        try:
            application = _ctl("regles-appliquer")
        except HTTPException:
            dnstv.ecrire_etat(ancien_etat)
            raise
        return {"nom": nom, "puits": corps.actif, "application": application}


@router.get("/auto/profil", dependencies=[Depends(require_lecture)])
def profil():
    reglage = dnstv_auto.reglage_depuis(_etat())
    graine = dnstv_profil.graine()
    agrege = dnstv_profil.charger_agrege()
    return {"min_appareils": reglage.min_appareils_agreg, "graine": graine, "agrege": agrege,
            "effectif": [{"domaine": d, "motif": m} for d, m in dnstv_profil.profil_effectif(graine, agrege)]}


# ── autorisations par appareil (#1965) : exceptions au puits complet ─────────────────────────────────────────────────────────
class AutoriserIn(BaseModel):
    domaine: str = Field(min_length=3, max_length=253)
    actif: bool = True


@router.post("/auto/appareils/{nom}/autoriser", dependencies=[Depends(require_jwt)])
def autoriser_domaine(nom: str, corps: AutoriserIn):
    """Exempte (actif) ou ré-expose (inactif) UN domaine du puits global pour cet appareil seulement. Rechargement d'Unbound (l'override n'est pas applicable à chaud)."""
    d = dnstv.valider_domaine(corps.domaine)
    if not d:
        raise HTTPException(422, "nom de domaine invalide")
    with _verrou():
        etat, ancien = _etat_et_copie()
        cs = _clients_du_nom(etat, nom)
        if any(c["mode"] != "auto" or not c.get("puits", True) for c in cs):
            raise HTTPException(422, "une autorisation n'a de sens que pour un appareil en mode auto avec puits complet (les autres ne voient pas le puits global)")
        cle = dnstv_regles.slug(nom)
        aut = {k: list(v) for k, v in etat.get("autorisations", {}).items()}
        liste = set(aut.get(cle, []))
        if corps.actif:
            if len(liste) >= dnstv.AUTORISATIONS_PAR_APPAREIL and d not in liste:
                raise HTTPException(422, f"{dnstv.AUTORISATIONS_PAR_APPAREIL} autorisations au plus par appareil")
            liste.add(d)
        else:
            liste.discard(d)
        if liste:
            aut[cle] = sorted(liste)
        else:
            aut.pop(cle, None)
        if aut:
            etat["autorisations"] = aut
        else:
            etat.pop("autorisations", None)
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        try:
            application = _ctl("regles-appliquer")
        except HTTPException:
            dnstv.ecrire_etat(ancien)
            raise
        return {"nom": nom, "autorisations": sorted(liste), "application": application}


@router.get("/auto/appareils/{nom}/refus", dependencies=[Depends(require_lecture)])
def refus_appareil(nom: str, minutes: int = 60):
    """Les noms REFUSÉS à cet appareil récemment (puits ou règle) : de quoi repérer ce qu'il faut autoriser quand un service ne démarre plus."""
    if not 1 <= minutes <= 1440:
        raise HTTPException(422, "minutes : entre 1 et 1440")
    etat = _etat()
    cs = _clients_du_nom(etat, nom)
    autorises = set(etat.get("autorisations", {}).get(dnstv_regles.slug(nom), []))
    evts = _magasin().recents([c["ip"] for c in cs], int(time.time()) - minutes * 60, 1000)
    par: dict = {}
    for e in evts:
        if e["decision"] == "BLOCKED":
            x = par.setdefault(e["domaine"], {"domaine": e["domaine"], "requetes": 0, "categorie": e["categorie"] or ""})
            x["requetes"] += 1
    refus = sorted(par.values(), key=lambda x: (-x["requetes"], x["domaine"]))[:30]
    for x in refus:
        x["autorise"] = x["domaine"] in autorises
    return {"nom": nom, "minutes": minutes, "refus": refus}



# ── panneau simplifié (#2174) : une carte par appareil, un interrupteur, une liste « ça ressemble à une pub » ─────────────────
class ProtectionIn(BaseModel):
    actif: bool


class SuspectIn(BaseModel):
    domaine: str = Field(min_length=3, max_length=253)


def _ignores_path():
    return dnstv.DOSSIER_ETAT / "suspects-ignores.json"


def _ignores() -> set:
    try:
        return {d for d in json.loads(_ignores_path().read_text(encoding="utf-8")) if isinstance(d, str)}
    except (OSError, ValueError):
        return set()


@router.get("/simple", dependencies=[Depends(require_lecture)])
def simple():
    """Tout ce que la page simplifiée affiche, en un appel."""
    etat = _etat()
    m = _magasin()
    depuis = int(time.time()) - 86400
    bloques = {}
    for e in m.recents(None, depuis, 1000):
        if e["decision"] == "BLOCKED":
            bloques[e["client"]] = bloques.get(e["client"], 0) + 1
    vus = {x["client"]: x["derniere_vue"] for x in m.par_client()}
    cartes = dnstv_simple.appareils(etat, bloques, vus)
    return {"actif": etat["actif"], "appareils": cartes, "protegees": sum(1 for c in cartes if c["protege"]),
            "bloques_24h": sum(bloques.values()), "dropin_present": dnstv.CONF_UNBOUND.is_file()}


@router.post("/simple/appareils/{nom}/protection", dependencies=[Depends(require_jwt)])
def basculer_protection(nom: str, corps: ProtectionIn):
    """Interrupteur : toutes les adresses de l'appareil passent en auto (ou off), puis le filtre est relu pour VÉRIFIER l'application."""
    with _verrou():
        etat, ancien = _etat_et_copie()
        cs = _clients_du_nom(etat, nom)
        for c in cs:
            c["mode"] = "auto" if corps.actif else "off"
        try:
            dnstv.ecrire_etat(etat)
        except dnstv.ErreurTV as e:
            _refuse(e)
        try:
            application = _ctl("apply")
        except HTTPException:
            dnstv.ecrire_etat(ancien)
            raise
        try:
            dropin = dnstv.CONF_UNBOUND.read_text(encoding="utf-8")
        except OSError:
            dropin = ""
        ecart = dnstv_simple.verifier_application(etat, nom, dropin)
        return {"nom": nom, "protege": corps.actif, "verifie": ecart is None, "ecart": ecart, "application": application}


@router.get("/simple/suspects", dependencies=[Depends(require_lecture)])
def suspects_pub(minutes: int = 60):
    """Noms encore servis qui ressemblent à de la pub (motif lisible), hors ceux déjà bloqués ou jugés légitimes."""
    if not 1 <= minutes <= 1440:
        raise HTTPException(422, "minutes : entre 1 et 1440")
    etat = _etat()
    noms = {c["ip"]: c["nom"] for c in etat["clients"] if c["mode"] != "off"}
    evts = _magasin().recents(list(noms), int(time.time()) - minutes * 60, 1000)
    p = _perso_path()
    deja = set(dnstv.lire_liste(p)[0]) if p.is_file() else set()
    return {"minutes": minutes, "suspects": dnstv_simple.suspects(evts, noms, _ignores(), deja | set(_table()))}


@router.post("/simple/suspects/legitime", dependencies=[Depends(require_jwt)])
def suspect_legitime(corps: SuspectIn):
    d = dnstv.valider_domaine(corps.domaine)
    if not d:
        raise HTTPException(422, "nom de domaine invalide")
    with _verrou():
        liste = sorted(_ignores() | {d})[-500:]
        dnstv.DOSSIER_ETAT.mkdir(parents=True, exist_ok=True)
        tmp = _ignores_path().with_suffix(".tmp")
        tmp.write_text(json.dumps(liste), encoding="utf-8")
        os.replace(tmp, _ignores_path())
    return {"domaine": d, "ignores": len(liste)}

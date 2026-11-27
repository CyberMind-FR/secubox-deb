# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Couches de menace nourries par nDPId (#4010).

sbxdpi tient, par adresse SOURCE externe qui ouvre des flux vers la box, les services visés (protocole L7/port), les risques nDPI et les
empreintes JA4 qu'il calcule depuis le ClientHello ; il l'écrit dans un fichier interne sur tmpfs (`/run/secubox/sbxdpi/couches-menaces.json`).
Ce module en tire trois couches :

- accès : services visés, en distinguant ce qui passe hors du WAF (tout ce qui n'est pas HTTP/TLS sur 80/443) ;
- raisons : risques nDPI, le bruit connu à part ;
- agent : l'empreinte TLS rapprochée de l'User-Agent que la même adresse a déclaré au WAF (waf-threats.log, lu de façon incrémentale).

Table de correspondance UA ↔ empreinte (volontairement simple, documentée ici et dans le README) :

| UA déclaré (WAF)          | forme du JA4 (profil_ja4)          | verdict                    |
|---------------------------|------------------------------------|----------------------------|
| navigateur                | « lib » (pas d'ALPN h2/h3, < 8 suites ou < 8 extensions) | outil probable : l'UA ment |
| outil / robot déclaré     | quelconque                         | outil déclaré              |
| navigateur                | « nav »                            | cohérent                   |
| absent (pas vu par le WAF)| « lib »                            | client de bibliothèque     |
| autre cas                 | —                                  | indéterminé                |

La forme d'un JA4 est une DÉDUCTION, jamais une identité d'application ; un « outil probable » n'est qu'un indice versé aux populations.

Sortie : `/var/cache/secubox/dpi/couches-menaces.json` (interne, adresses comprises, pour les populations #4005), en double tampon — une passe
dégradée (relevé de sbxdpi absent ou en chauffe) n'écrase jamais un relevé complet récent ; écriture tmp + rename. La route n'en rend qu'une vue
SANS adresse (`vue_publique`) : chaque source y est une référence opaque, salée par démarrage.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

try:
    from api.sbxdpi_bridge import BRUIT, profil_ja4
except ImportError:                                           # exécution depuis le répertoire api/
    from sbxdpi_bridge import BRUIT, profil_ja4

log = logging.getLogger("secubox.ndpid.couches")

RELEVE_SBXDPI = Path("/run/secubox/sbxdpi/couches-menaces.json")
JOURNAL_WAF = Path("/var/log/secubox/waf/waf-threats.log")
CACHE = Path("/var/cache/secubox/dpi/couches-menaces.json")
TTL = 60                                                      # secondes entre deux calculs
MAX_UA = 8192                                                 # adresses retenues depuis le journal du WAF
PREMIERE_LECTURE = 2 * 1024 * 1024                            # au premier passage, seulement la fin du journal
PAR_PASSE = 4 * 1024 * 1024                                   # lecture incrémentale bornée par passe
VIA_WAF = {("HTTP", 80), ("TLS", 443), ("HTTP", 443), ("QUIC", 443)}

_NAV = re.compile(r"mozilla/5\.0.*(chrome|firefox|safari|edg|opr)/", re.I)
_OUTIL = re.compile(r"curl|wget|python|aiohttp|httpx|go-http|okhttp|java/|libwww|perl|ruby|node-fetch|axios|nuclei|zgrab|masscan|nmap|sqlmap|"
                    r"nikto|gobuster|ffuf|dirbuster|wpscan|httpclient|scrapy|headless", re.I)
_ROBOT = re.compile(r"bot|crawler|spider|slurp|scan", re.I)


def famille_ua(ua: str) -> str:
    """« navigateur », « outil », « robot », « autre », ou « absent » (UA vide)."""
    ua = (ua or "").strip()
    if not ua:
        return "absent"
    if _OUTIL.search(ua):
        return "outil"
    if _ROBOT.search(ua):
        return "robot"
    if _NAV.search(ua):
        return "navigateur"
    return "autre"


def verdict_agent(ua_fam: str, ja4_fam: str) -> str:
    if ua_fam in ("outil", "robot"):
        return "outil_declare"
    if ua_fam == "navigateur" and ja4_fam == "lib":
        return "outil_probable"
    if ua_fam == "navigateur" and ja4_fam == "nav":
        return "coherent"
    if ua_fam in ("absent", "") and ja4_fam == "lib":
        return "client_bibliotheque"
    return "indetermine"


class LecteurWaf:
    """Lecture incrémentale de waf-threats.log : dernière UA (et outil identifié) par adresse, bornée. Rotation détectée par l'inode."""

    def __init__(self, chemin: Path = JOURNAL_WAF):
        self.chemin = chemin
        self.inode: Optional[int] = None
        self.pos = 0
        self.ua: Dict[str, dict] = {}

    def lire(self) -> Dict[str, dict]:
        try:
            st = os.stat(self.chemin)
        except OSError:
            return self.ua
        if st.st_ino != self.inode or st.st_size < self.pos:
            self.inode = st.st_ino
            self.pos = max(0, st.st_size - PREMIERE_LECTURE) if self.pos == 0 else 0
        if st.st_size == self.pos:
            return self.ua
        try:
            with open(self.chemin, "rb") as f:
                f.seek(self.pos)
                bloc = f.read(PAR_PASSE)
        except OSError:
            return self.ua
        fin = bloc.rfind(b"\n")
        if fin < 0:
            return self.ua
        self.pos += fin + 1
        for ligne in bloc[:fin].splitlines():
            try:
                d = json.loads(ligne)
            except ValueError:
                continue
            ip = d.get("client_ip") if isinstance(d, dict) else None
            if not ip:
                continue
            if ip not in self.ua and len(self.ua) >= MAX_UA:
                self.ua.pop(next(iter(self.ua)))
            self.ua.pop(ip, None)                             # réinsertion : l'ordre du dict = ancienneté
            self.ua[ip] = {"ua": str(d.get("user_agent") or "")[:300], "outil": str(d.get("tool") or "")[:40]}
        return self.ua


def _hors_waf(service: str) -> bool:
    proto, _, port = service.rpartition("/")
    try:
        return (proto, int(port)) not in VIA_WAF
    except ValueError:
        return True


def calculer(releve: Optional[dict], ua: Dict[str, dict]) -> dict:
    """Relevé interne : par source, les trois couches et le verdict d'agent. `complet` suit celui de sbxdpi."""
    maintenant = int(time.time())
    if not isinstance(releve, dict) or not isinstance(releve.get("sources"), dict):
        return {"version": 1, "genere": maintenant, "complet": False, "raison": "relevé sbxdpi absent", "sources": {}}
    sources = {}
    for ip, s in releve["sources"].items():
        if not isinstance(s, dict):
            continue
        services = {k: int(v) for k, v in (s.get("services") or {}).items()}
        risques = {k: int(v) for k, v in (s.get("risques") or {}).items()}
        ja4s = s.get("ja4") or {}
        ja4 = max(sorted(ja4s), key=lambda k: ja4s[k]) if ja4s else ""
        ja4_fam = profil_ja4(ja4).get("famille_deduite", "") if ja4 else ""
        w = ua.get(ip) or {}
        ua_fam = famille_ua(w.get("ua", "")) if ip in ua else ""
        sources[ip] = {
            "flux": int(s.get("flux") or 0), "octets": int(s.get("octets") or 0),
            "premier": int(s.get("premier") or 0), "dernier": int(s.get("dernier") or 0),
            "services": services, "hors_waf": sorted(k for k in services if _hors_waf(k)),
            "risques": risques, "risques_notables": sorted(k for k in risques if k not in BRUIT),
            "ja4": ja4, "ja4_famille": ja4_fam, "vu_par_waf": ip in ua, "ua_famille": ua_fam or "absent",
            "outil_waf": w.get("outil", ""), "agent": verdict_agent(ua_fam or "absent", ja4_fam),
        }
    return {"version": 1, "genere": maintenant, "complet": bool(releve.get("complet")), "fenetre_s": int(releve.get("fenetre_s") or 0),
            "releve_sbxdpi": int(releve.get("genere") or 0), "sources": sources}


def ecrire_double_tampon(chemin: Path, data: dict, garde_s: int = 2 * 86400) -> bool:
    """tmp + rename ; une passe dégradée ne remplace pas un relevé complet de moins de `garde_s`. Rend True si écrit."""
    if not data.get("complet"):
        try:
            ancien = json.loads(chemin.read_text())
            if ancien.get("complet") and data.get("genere", 0) - int(ancien.get("genere") or 0) < garde_s:
                return False
        except (OSError, ValueError):
            pass                                              # pas de relevé antérieur lisible : le dégradé est mieux que rien
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_name(chemin.name + ".tmp")
    tmp.write_text(json.dumps(data, separators=(",", ":")))
    os.chmod(tmp, 0o640)
    os.replace(tmp, chemin)
    return True


_SEL = secrets.token_bytes(16)


def _ref(ip: str) -> str:
    return hashlib.blake2s(ip.encode(), key=_SEL, digest_size=5).hexdigest()


def vue_publique(data: dict, limite: int = 20) -> dict:
    """Agrégats et sources ANONYMES (référence salée par démarrage) : aucune adresse ne sort par l'API."""
    src = data.get("sources") or {}
    services: Dict[str, dict] = {}
    raisons: Dict[str, dict] = {}
    agents: Dict[str, int] = {}
    for s in src.values():
        for k, n in s["services"].items():
            e = services.setdefault(k, {"service": k, "sources": 0, "flux": 0, "hors_waf": _hors_waf(k)})
            e["sources"] += 1
            e["flux"] += n
        for k, n in s["risques"].items():
            e = raisons.setdefault(k, {"risque": k, "sources": 0, "flux": 0, "bruit": k in BRUIT})
            e["sources"] += 1
            e["flux"] += n
        agents[s["agent"]] = agents.get(s["agent"], 0) + 1

    def score(s):
        return (s["agent"] == "outil_probable") * 1000 + 10 * len(s["risques_notables"]) + len(s["hors_waf"])

    top = sorted(src.items(), key=lambda kv: (-score(kv[1]), -kv[1]["flux"]))[:limite]
    return {
        "genere": data.get("genere"), "complet": bool(data.get("complet")), "fenetre_s": data.get("fenetre_s", 0),
        "sources_externes": len(src), "sources_hors_waf": sum(1 for s in src.values() if s["hors_waf"]),
        "services": sorted(services.values(), key=lambda e: (-e["sources"], -e["flux"]))[:limite],
        "raisons": sorted(raisons.values(), key=lambda e: (e["bruit"], -e["sources"], -e["flux"]))[:limite],
        "agents": agents,
        "sources": [{"ref": _ref(ip), "flux": s["flux"], "hors_waf": s["hors_waf"][:6], "risques_notables": s["risques_notables"][:6],
                     "ja4_famille": s["ja4_famille"], "ua_famille": s["ua_famille"], "agent": s["agent"]} for ip, s in top],
    }


class CouchesMenaces:
    """Tâche de fond (ou calcul paresseux sous l'agrégateur, qui ne lance pas le démarrage des sous-applications) ; synchrone, à appeler
    hors de la boucle (asyncio.to_thread)."""

    def __init__(self, releve: Path = RELEVE_SBXDPI, cache: Path = CACHE, waf: Optional[LecteurWaf] = None, ttl: int = TTL):
        self.releve, self.cache, self.ttl = releve, cache, ttl
        self.waf = waf or LecteurWaf()
        self.dernier = 0.0

    def perime(self) -> bool:
        return time.monotonic() - self.dernier >= self.ttl

    def rafraichir(self) -> dict:
        self.dernier = time.monotonic()
        try:
            releve = json.loads(self.releve.read_text())
        except (OSError, ValueError):
            releve = None
        data = calculer(releve, self.waf.lire())
        try:
            ecrire_double_tampon(self.cache, data)
        except OSError as e:                                  # la route rend quand même le dernier bon relevé
            log.warning("couches de menace : écriture du cache impossible : %s", e)
        return self.lire()

    def lire(self) -> dict:
        try:
            return json.loads(self.cache.read_text())
        except (OSError, ValueError):
            return {"complet": False, "sources": {}}

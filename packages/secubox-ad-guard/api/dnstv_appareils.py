# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: SBX TV PRIVACY, lot 1 « socle appareil » (#3374).

Un appareil = une adresse MAC. `clients` de l'état (une entrée par adresse, lue par le contrôleur root pour Unbound) ne change pas de forme ;
on y ajoute `appareils` (MAC -> nom, profil corrigé à la main) et `schema: 2`. Ce module :

- migre un état v1 sans rien perdre (sauvegarde unique `etat.json.avant-3374`, regroupement par MAC, mode le plus fréquent) ;
- lit l'inventaire du NAC EN LECTURE SEULE (`/var/lib/secubox/nac/devices.db`), avec repli sur `ip neigh` quand le NAC manque ;
- déduit un profil d'équipement des PREUVES du NAC (osdetect, OUI, nom DHCP, type), jamais du nom donné dans ad-guard ;
- rend la vue par MAC servie par l'API, et applique la correction manuelle du profil, qui prime toujours.

Conception : docs/superpowers/specs/2026-11-01-sbx-tv-privacy-lot1-design.md.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import re
import sqlite3
import stat
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

try:
    from . import dnstv
except ImportError:                                  # lancé hors paquet
    from api import dnstv

logger = logging.getLogger("secubox.ad-guard.dnstv-appareils")

NAC_DB = Path(os.environ.get("SECUBOX_ADGUARD_NAC_DB", "/var/lib/secubox/nac/devices.db"))
NAC_TAILLE_MAX = 64 * 1024 * 1024
NAC_LIGNES_MAX = 4096
ETAT_TAILLE_MAX = 1024 * 1024
SAUVEGARDE = "etat.json.avant-3374"


class AppareilInconnu(dnstv.ErreurTV):
    """MAC absente du périmètre : l'API répond 404."""


# ── migration v1 -> v2 ─────────────────────────────────────────────────────────────────────────────────

def _elire(entrees: List[Tuple[int, dict]]) -> dict:
    """Entrée qui donne le mode d'un appareil : mode le plus fréquent ; à égalité, l'entrée la plus récente (`ajoute`, puis rang dans la liste)."""
    compte = Counter(c["mode"] for _, c in entrees)
    meilleur = max(compte.values())
    candidates = [(c.get("ajoute", 0), i, c) for i, c in entrees if compte[c["mode"]] == meilleur]
    return max(candidates, key=lambda t: (t[0], t[1]))[2]


def _par_mac(clients: List[dict]) -> Dict[str, List[Tuple[int, dict]]]:
    g: Dict[str, List[Tuple[int, dict]]] = {}
    for i, c in enumerate(clients):
        if c.get("mac"):
            g.setdefault(c["mac"], []).append((i, c))
    return g


def migrer(brut: dict, maintenant: int) -> Tuple[dict, dict]:
    """(état v2 validé, rapport). Pur : n'écrit rien. Un état déjà v2 est rendu tel quel (idempotence).
    Rapport : appareils (MAC regroupées), modes_changes (adresses alignées), fusion_refusee (l'alignement aurait donné un état invalide)."""
    etat = dnstv.valider_etat(brut)
    if etat.get("schema") == dnstv.SCHEMA_ETAT:
        return etat, {"appareils": len(etat.get("appareils", {})), "modes_changes": 0, "fusion_refusee": False}
    groupes = _par_mac(etat["clients"])
    appareils: Dict[str, dict] = {}
    aligne = copy.deepcopy(etat)
    changes = 0
    for mac, entrees in groupes.items():
        elu = _elire(entrees)
        appareils[mac] = {"nom": elu["nom"]}
        for i, c in entrees:
            if c["mode"] != elu["mode"]:
                aligne["clients"][i]["mode"] = elu["mode"]
                changes += 1
    refusee = False
    try:
        nouvel = dnstv.valider_etat(dict(aligne, schema=dnstv.SCHEMA_ETAT, appareils=appareils))
    except dnstv.ErreurTV as e:
        logger.warning("migration #3374 : alignement des modes refusé (%s), modes d'origine gardés", e)
        nouvel = dnstv.valider_etat(dict(etat, schema=dnstv.SCHEMA_ETAT, appareils=appareils))
        changes, refusee = 0, True
    return nouvel, {"appareils": len(appareils), "modes_changes": changes, "fusion_refusee": refusee, "date": maintenant}


def _lire_octets(chemin: Path, plafond: int) -> bytes:
    """Lecture d'un fichier ordinaire sans suivre de lien, bornée en taille."""
    fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > plafond:
            raise OSError("fichier refusé (type ou taille)")
        return os.read(fd, plafond + 1)[:plafond]
    finally:
        os.close(fd)


def migrer_fichier(dossier: Optional[Path] = None, maintenant: Optional[int] = None) -> Optional[dict]:
    """Migre `etat.json` sur place s'il est v1. Rend le rapport, ou None s'il n'y avait rien à faire (absent, déjà v2, illisible : jamais deviné).
    L'appelant tient le verrou commun des règles. La sauvegarde n'est créée qu'UNE fois et n'est jamais écrasée."""
    d = dossier or dnstv.DOSSIER_ETAT
    try:
        brut_octets = _lire_octets(d / "etat.json", ETAT_TAILLE_MAX)
        brut = json.loads(brut_octets)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        logger.warning("migration #3374 : état illisible, laissé tel quel (%s)", e)
        return None
    if isinstance(brut, dict) and brut.get("schema") == dnstv.SCHEMA_ETAT:
        return None
    try:
        nouvel, rapport = migrer(brut, maintenant or int(time.time()))
    except dnstv.ErreurTV as e:
        logger.warning("migration #3374 : état refusé, laissé tel quel (%s)", e)
        return None
    try:
        fd = os.open(d / SAUVEGARDE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        try:
            os.fchmod(fd, 0o640)
            os.write(fd, brut_octets)
        finally:
            os.close(fd)
    except FileExistsError:
        pass                                                      # première sauvegarde gardée
    dnstv.ecrire_etat(nouvel, d)
    logger.info("migration #3374 : %s", rapport)
    return rapport


# ── inventaire du NAC (lecture seule) ─────────────────────────────────────────────────────────────────

_COLONNES_NAC = ("mac", "ip", "hostname", "oui_vendor", "device_type", "os", "os_source", "device_subtype", "mac_random", "last_seen")


def lire_inventaire_nac(chemin: Optional[Path] = None, taille_max: int = NAC_TAILLE_MAX) -> Dict[str, dict]:
    """MAC -> ligne du NAC. Fichier ordinaire (pas de lien), propriétaire nous ou root, non inscriptible par « autres », taille bornée ;
    ouverture SQLite `mode=ro`, aucune écriture chez le NAC. Toute erreur rend {} : ad-guard continue sans NAC (repli `ip neigh`)."""
    p = Path(chemin or NAC_DB)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return {}
    except OSError as e:
        logger.warning("inventaire NAC illisible (%s)", e)
        return {}
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (os.geteuid(), 0) or st.st_mode & 0o002 or st.st_size > taille_max:
        logger.warning("inventaire NAC refusé : %s (type, propriétaire, droits ou taille)", p)
        return {}
    out: Dict[str, dict] = {}
    try:
        cx = sqlite3.connect(f"file:{urllib.parse.quote(str(p))}?mode=ro", uri=True, timeout=2)
        try:
            lignes = cx.execute(f"SELECT {', '.join(_COLONNES_NAC)} FROM devices ORDER BY last_seen DESC LIMIT ?", (NAC_LIGNES_MAX,)).fetchall()
        finally:
            cx.close()
    except sqlite3.Error as e:
        logger.warning("inventaire NAC illisible (%s)", e)
        return {}
    for valeurs in lignes:
        ligne = dict(zip(_COLONNES_NAC, valeurs))
        mac = ligne["mac"]
        if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac) or mac in out:
            continue
        for k, v in ligne.items():
            if isinstance(v, str):
                ligne[k] = v[:120]
        out[mac] = ligne
    return out


# ── profils d'équipement ──────────────────────────────────────────────────────────────────────────────

_CONF_SOURCE = (("dhcp-vendor-class:", 90), ("user-agent:", 85), ("dns:", 80), ("hostname:", 60), ("empreinte-nac:", 50))
_SOUS_TYPES_TV = {"télévision", "décodeur", "streaming", "récepteur multimédia"}
_NOM_FREEBOX = re.compile(r"freebox-?player|^player-", re.I)
_NOM_APPLETV = re.compile(r"apple-?tv", re.I)
_NOM_GOOGLETV = re.compile(r"google-?tv|chromecast", re.I)
_OBSERVATION = (
    (re.compile(r"(^|\.)(samsungcloudsolution\.com|samsungotn\.net|samsungads\.com)$"), "SAMSUNG_TIZEN"),
    (re.compile(r"(^|\.)(lgtvsdp\.com|lgappstv\.com)$"), "LG_WEBOS"),
)


def _conf_os(os_source: Optional[str]) -> int:
    for prefixe, conf in _CONF_SOURCE:
        if (os_source or "").startswith(prefixe):
            return conf
    return 50


def _mac_aleatoire(ligne: dict) -> bool:
    mac = ligne.get("mac") or ""
    try:
        bit = bool(int(mac.split(":")[0], 16) & 0x02) if ":" in mac else False
    except ValueError:
        bit = False
    return bool(ligne.get("mac_random")) or bit


def _profil(type_: str, source: str, confiance: int, preuves: List[str]) -> dict:
    return {"type": type_, "source": source, "confiance": max(0, min(100, int(confiance))), "preuves": preuves}


def profil_depuis_nac(ligne: dict) -> dict:
    """Profil déduit des preuves du NAC. Une MAC aléatoire n'est jamais typée par son OUI ; sans preuve : INCONNU, confiance 0."""
    os_ = ligne.get("os") or ""
    src = ligne.get("os_source") or ""
    sous = ligne.get("device_subtype") or ""
    nom = ligne.get("hostname") or ""
    typ = ligne.get("device_type") or ""
    oui = "" if _mac_aleatoire(ligne) else (ligne.get("oui_vendor") or "")
    p_os = [f"os:{os_} ({src})"] if os_ else []
    if "Tizen" in os_:
        return _profil("SAMSUNG_TIZEN", "nac", _conf_os(src), p_os)
    if "webOS" in os_:
        return _profil("LG_WEBOS", "nac", _conf_os(src), p_os)
    if _NOM_FREEBOX.search(nom):
        fb = "freebox" in oui.lower()
        return _profil("FREEBOX_PLAYER", "nac", 70 if fb else 60, [f"nom DHCP:{nom}"] + ([f"OUI:{oui}"] if fb else []))
    if "freebox" in oui.lower():
        return _profil("FREEBOX_PLAYER", "nac", 50, [f"OUI:{oui}"])
    if _NOM_APPLETV.search(nom):
        return _profil("APPLE_TV", "nac", 60, [f"nom DHCP:{nom}"])
    if "apple" in oui.lower() and sous in ("streaming", "récepteur multimédia"):
        return _profil("APPLE_TV", "nac", 55, [f"OUI:{oui}", f"sous-type:{sous}"])
    if "Google Cast" in os_:
        return _profil("GOOGLE_TV", "nac", _conf_os(src), p_os)
    if _NOM_GOOGLETV.search(nom):
        return _profil("GOOGLE_TV", "nac", 60, [f"nom DHCP:{nom}"] + p_os)
    if os_.startswith("Android") and (sous in _SOUS_TYPES_TV or typ == "smart_tv"):
        return _profil("ANDROID_TV", "nac", min(_conf_os(src), 70), p_os + [f"type:{sous or typ}"])
    if sous == "télévision" or typ == "smart_tv":
        return _profil("GENERIC_SMART_TV", "nac", 40, [f"type:{sous or typ}"])
    return _profil("INCONNU", "nac", 0, [])


def profil_par_observation(domaines: Iterable[str]) -> Optional[dict]:
    """Profil tiré des domaines de connectivité qu'ad-guard a vu passer (sans NAC, ou NAC sans conclusion). None sans preuve."""
    for d in domaines or []:
        d = (d or "").lower().rstrip(".")
        for motif, type_ in _OBSERVATION:
            if motif.search(d):
                return _profil(type_, "observation", 70, [f"dns:{d}"])
    return None


# ── vue par MAC et correction manuelle ─────────────────────────────────────────────────────────────────

def _domaines(source: Union[None, Dict[str, List[str]], Callable[[str], List[str]]], ips: List[str]) -> List[str]:
    if source is None:
        return []
    out: List[str] = []
    for ip in ips:
        out += (source(ip) if callable(source) else source.get(ip, [])) or []
    return out


def _choisir_profil(manuel: Optional[dict], ligne_nac: Optional[dict], domaines_de, ips: List[str]) -> dict:
    if manuel:
        return dict(manuel, preuves=["correction manuelle"])
    p = profil_depuis_nac(ligne_nac) if ligne_nac else None
    if p and p["type"] != "INCONNU":
        return p
    obs = profil_par_observation(_domaines(domaines_de, ips))
    return obs or _profil("INCONNU", "nac", 0, [])


def vue_appareils(etat: dict, nac: Dict[str, dict], voisins: Dict[str, str], domaines_de=None) -> List[dict]:
    """Un élément par MAC (ses IP : clients déclarés, NAC, `ip neigh`), plus un par nom pour les clients sans MAC (`mac` = None).
    `domaines_de` : table ip -> domaines, ou fonction ip -> domaines, pour le profil par observation."""
    appareils = etat.get("appareils", {})
    out: List[dict] = []
    for mac, entrees in _par_mac(etat["clients"]).items():
        cs = [c for _, c in entrees]
        ips = {c["ip"] for c in cs} | {ip for ip, m in voisins.items() if m == mac}
        ligne = nac.get(mac)
        if ligne and ligne.get("ip"):
            try:
                ips.add(dnstv._ip(ligne["ip"]))
            except dnstv.ErreurTV:
                pass                                              # adresse NAC illisible : ignorée, jamais recopiée
        ips_triees = sorted(ips)
        p = _choisir_profil(appareils.get(mac, {}).get("profil"), ligne, domaines_de, ips_triees)
        out.append({"mac": mac, "nom": appareils.get(mac, {}).get("nom") or cs[0]["nom"], "noms": sorted({c["nom"] for c in cs}),
                    "ips": ips_triees, "mode": _elire(entrees)["mode"], "profil": p["type"], "profil_source": p["source"],
                    "profil_confiance": p["confiance"], "preuves": p["preuves"], "nac": ligne is not None})
    par_nom: Dict[str, List[Tuple[int, dict]]] = {}
    for i, c in enumerate(etat["clients"]):
        if not c.get("mac"):
            par_nom.setdefault(c["nom"], []).append((i, c))
    for nom, entrees in par_nom.items():
        ips_triees = sorted(c["ip"] for _, c in entrees)
        p = _choisir_profil(None, None, domaines_de, ips_triees)
        out.append({"mac": None, "nom": nom, "noms": [nom], "ips": ips_triees, "mode": _elire(entrees)["mode"], "profil": p["type"],
                    "profil_source": p["source"], "profil_confiance": p["confiance"], "preuves": p["preuves"], "nac": False})
    return out


def corriger_profil(etat: dict, mac: str, type_: Optional[str], maintenant: int) -> dict:
    """Nouvel état (copie) avec le profil manuel de `mac`, ou sans correction si `type_` est None. La MAC doit être dans le périmètre."""
    if not isinstance(mac, str) or not dnstv.MAC_RE.match(mac):
        raise AppareilInconnu("appareil inconnu")
    if type_ is not None and type_ not in dnstv.PROFILS:
        raise dnstv.ErreurTV("type de profil inconnu")
    e = copy.deepcopy(etat)
    cs = [c for c in e["clients"] if c.get("mac") == mac]
    appareils = e.setdefault("appareils", {})
    if not cs and mac not in appareils:
        raise AppareilInconnu("appareil inconnu")
    a = appareils.setdefault(mac, {"nom": cs[0]["nom"] if cs else mac})
    if type_ is None:
        a.pop("profil", None)
    else:
        a["profil"] = {"type": type_, "source": "manuel", "confiance": 100, "maj": int(maintenant)}
    e["schema"] = dnstv.SCHEMA_ETAT
    return dnstv.valider_etat(e)
